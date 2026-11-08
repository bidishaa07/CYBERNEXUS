"""Controlled candidate training. Production promotion is deliberately separate."""
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from backend.app.core.config import settings
from backend.app.db.session import SessionLocal
from backend.app.models.models import MLDatasetVersion, MLModelVersion, MLTrainingRun, MessageReview, MessageReviewFeedback, MessageContent
from backend.app.services.ml_registry import DATASET_ROOT, MODEL_ROOT, production_artifact, sha256_file, validate_dataset

def _metrics(labels, predictions, probabilities) -> dict:
    matrix=confusion_matrix(labels,predictions).tolist(); tn,fp,fn,tp=confusion_matrix(labels,predictions,labels=[0,1]).ravel()
    return {"accuracy":accuracy_score(labels,predictions),"precision":precision_score(labels,predictions,zero_division=0),"recall":recall_score(labels,predictions,zero_division=0),"f1":f1_score(labels,predictions,zero_division=0),"macro_f1":f1_score(labels,predictions,average="macro",zero_division=0),"weighted_f1":f1_score(labels,predictions,average="weighted",zero_division=0),"confusion_matrix":matrix,"false_positive_rate":fp / max(fp+tn,1),"false_negative_rate":fn / max(fn+tp,1),"roc_auc":roc_auc_score(labels,probabilities) if len(set(labels)) == 2 else None,"pr_auc":average_precision_score(labels,probabilities) if len(set(labels)) == 2 else None,"brier_score":brier_score_loss(labels,probabilities)}

def _load_text_dataset(dataset: MLDatasetVersion) -> pd.DataFrame:
    path=(DATASET_ROOT / dataset.source).resolve()
    if DATASET_ROOT not in path.parents or not path.is_file(): raise ValueError("approved_dataset_path_unavailable")
    frame=pd.read_csv(path,nrows=settings.ml_training_max_rows,usecols=lambda c: c in {"body","text","subject","label"},on_bad_lines="skip")
    column="body" if "body" in frame.columns else "text" if "text" in frame.columns else None
    if not column or "label" not in frame.columns: raise ValueError("dataset_requires_body_or_text_and_label")
    text=frame[column].fillna("").astype(str)
    if "subject" in frame.columns: text=frame["subject"].fillna("").astype(str)+"\n"+text
    labels=pd.to_numeric(frame["label"],errors="coerce"); frame=pd.DataFrame({"text":text,"label":labels}).dropna(); frame=frame[frame["text"].str.len() > 3]; frame["label"]=frame["label"].astype(int); frame=frame[frame["label"].isin([0,1])].drop_duplicates(subset=["text"])
    if frame["label"].nunique() < 2: raise ValueError("dataset_requires_both_classes")
    return frame

def run_training(training_run_id: int) -> dict:
    db=SessionLocal(); run=db.get(MLTrainingRun,training_run_id)
    if not run: db.close(); raise ValueError("training_run_not_found")
    try:
        run.status="RUNNING"; run.started_at=datetime.now(timezone.utc); db.commit()
        dataset=db.get(MLDatasetVersion,run.dataset_version_id)
        if not dataset or dataset.approval_status != "APPROVED": raise ValueError("dataset_not_approved")
        quality=validate_dataset(dataset.source,settings.ml_training_max_rows)
        if quality["checksum"] != dataset.checksum: raise ValueError("dataset_checksum_changed")
        if quality["validation_status"] != "VALID": raise ValueError("dataset_validation_failed")
        data=_load_text_dataset(dataset); train_valid,test=train_test_split(data,test_size=.2,random_state=42,stratify=data["label"]); train,valid=train_test_split(train_valid,test_size=.125,random_state=42,stratify=train_valid["label"])
        approved_feedback=[]
        for feedback, review, content in db.query(MessageReviewFeedback, MessageReview, MessageContent).join(MessageReview, MessageReview.id == MessageReviewFeedback.review_id).join(MessageContent, MessageContent.message_analysis_id == MessageReview.message_analysis_id).filter(MessageReviewFeedback.approval_status == "APPROVED", MessageReviewFeedback.label.in_(["MALICIOUS","BENIGN"])).all():
            approved_feedback.append({"text":content.content_bytes.decode(errors="replace"),"label":1 if feedback.label == "MALICIOUS" else 0})
        if approved_feedback: train=pd.concat([train,pd.DataFrame(approved_feedback)],ignore_index=True).drop_duplicates(subset=["text"])
        pipeline=Pipeline([("tfidf",TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=150000,sublinear_tf=True)),("classifier",LogisticRegression(max_iter=300,class_weight="balanced"))]); pipeline.fit(train["text"],train["label"])
        valid_prob=pipeline.predict_proba(valid["text"])[:,1]; valid_pred=(valid_prob >= .5).astype(int); test_prob=pipeline.predict_proba(test["text"])[:,1]; test_pred=(test_prob >= .5).astype(int)
        metrics={"validation":_metrics(valid["label"],valid_pred,valid_prob),"test":_metrics(test["label"],test_pred,test_prob),"split":{"train_rows":len(train),"validation_rows":len(valid),"test_rows":len(test),"random_state":42},"approved_feedback_count":len(approved_feedback)}
        production=production_artifact(); baseline=None
        if production.exists():
            try:
                old=joblib.load(production)["pipeline"]; old_prob=old.predict_proba(test["text"])[:,1]; baseline=_metrics(test["label"],(old_prob >= .5).astype(int),old_prob)
            except Exception: baseline={"status":"UNAVAILABLE"}
        metrics["comparison"]={"production":baseline,"candidate_f1":metrics["test"]["f1"],"max_allowed_f1_regression":settings.ml_max_f1_regression,"accepted_by_threshold":metrics["test"]["f1"] >= settings.ml_min_f1 and metrics["test"]["false_negative_rate"] <= settings.ml_max_false_negative_rate and (not baseline or baseline.get("status") == "UNAVAILABLE" or metrics["test"]["f1"] + settings.ml_max_f1_regression >= baseline.get("f1",0))}
        version=f"retrain-{training_run_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"; artifact=MODEL_ROOT/"candidates"/f"{version}.joblib"; artifact.parent.mkdir(parents=True,exist_ok=True)
        joblib.dump({"pipeline":pipeline,"metrics":metrics,"trained_rows":len(train),"model_name":"tfidf-logistic-message-classifier","model_version":version,"dataset_version":dataset.dataset_id+"-"+dataset.version,"preprocessing_version":dataset.preprocessing_version,"feature_config":{"ngram_range":[1,2],"min_df":2,"max_features":150000,"sublinear_tf":True},"hyperparameters":{"max_iter":300,"class_weight":"balanced"}},artifact)
        model=MLModelVersion(model_id="tfidf-logistic-message-classifier",version=version,name="tfidf-logistic-message-classifier",algorithm="TF-IDF + Logistic Regression",dataset_version_id=dataset.id,artifact_location=str(artifact.relative_to(Path(__file__).resolve().parents[3])),artifact_checksum=sha256_file(artifact),feature_config_json=json.dumps({"ngram_range":[1,2],"min_df":2}),hyperparameters_json=json.dumps({"max_iter":300,"class_weight":"balanced"}),metrics_json=json.dumps(metrics),status="CANDIDATE" if metrics["comparison"]["accepted_by_threshold"] else "REJECTED",created_by=run.created_by)
        db.add(model); db.flush(); run.model_version_id=model.id; run.metrics_json=json.dumps(metrics); run.status="COMPLETED" if model.status == "CANDIDATE" else "EVALUATION_FAILED"; run.completed_at=datetime.now(timezone.utc); db.commit(); return {"training_run_id":run.id,"model_version_id":model.id,"status":run.status,"model_status":model.status,"metrics":metrics}
    except Exception as exc:
        db.rollback(); run=db.get(MLTrainingRun,training_run_id); run.status="FAILED"; run.error=type(exc).__name__+": "+str(exc)[:220]; run.completed_at=datetime.now(timezone.utc); db.commit(); raise
    finally: db.close()
