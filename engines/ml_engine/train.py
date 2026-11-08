"""Train/evaluate the message classifier from the workspace datasets."""
import argparse, json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

def load_rows(path, max_rows):
    parts=[]; seen=0
    for chunk in pd.read_csv(path,usecols=lambda c:c in {"body","label","subject"},chunksize=20000,on_bad_lines="skip"):
        body=chunk.get("body",pd.Series("",index=chunk.index)).fillna("").astype(str)
        if "subject" in chunk: body=chunk["subject"].fillna("").astype(str)+"\n"+body
        labels=pd.to_numeric(chunk.get("label"),errors="coerce"); keep=labels.notna() & body.str.len().gt(3)
        parts.append(pd.DataFrame({"text":body[keep],"label":labels[keep].astype(int)})); seen+=int(keep.sum())
        if seen>=max_rows: break
    return pd.concat(parts,ignore_index=True).head(max_rows).query("label in [0,1]")

def main():
    p=argparse.ArgumentParser(); p.add_argument("--dataset",default="dataset/Merged_Dataset.csv"); p.add_argument("--max-rows",type=int,default=100000); p.add_argument("--output",default="models/phishing_message_model.joblib"); a=p.parse_args()
    data=load_rows(a.dataset,a.max_rows)
    if data.label.nunique()<2: raise SystemExit("Dataset needs both 0 and 1 labels")
    xt,xv,yt,yv=train_test_split(data.text,data.label,test_size=.2,random_state=42,stratify=data.label)
    pipeline=Pipeline([("tfidf",TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=150000,sublinear_tf=True)),("classifier",LogisticRegression(max_iter=300,class_weight="balanced"))]); pipeline.fit(xt,yt); pred=pipeline.predict(xv)
    metrics={"precision":precision_score(yv,pred,zero_division=0),"recall":recall_score(yv,pred,zero_division=0),"f1":f1_score(yv,pred,zero_division=0),"accuracy":accuracy_score(yv,pred),"confusion_matrix":confusion_matrix(yv,pred).tolist(),"test_rows":len(yv),"label_distribution":data.label.value_counts().to_dict()}
    out=Path(a.output); out.parent.mkdir(parents=True,exist_ok=True); joblib.dump({"pipeline":pipeline,"metrics":metrics,"trained_rows":len(data),"model_name":"tfidf-logistic-message-classifier"},out); print(json.dumps(metrics,indent=2))
if __name__=="__main__": main()
