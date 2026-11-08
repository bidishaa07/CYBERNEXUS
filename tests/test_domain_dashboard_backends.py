from backend.app.engines.infrastructure_graph import build_graph
from backend.app.engines.ipinfo import _normalise

def test_ipinfo_extended_fields_remain_unknown_when_provider_omits_them():
    result=_normalise('8.8.8.8', {'asn': {'asn': 'AS15169', 'name': 'Google LLC', 'domain': 'google.com'}, 'country_code':'US'})
    assert result['asn_number']=='AS15169'
    assert 'hosting_provider' in result['unavailable_fields']
    assert result['classification'] is None

def test_infrastructure_graph_deduplicates_nodes_and_preserves_provenance():
    graph=build_graph('example.com', {'domain': {'registered_domain':'example.com'}, 'infrastructure': {'ips':['8.8.8.8'], 'providers':[{'ip':'8.8.8.8','asn_number':'AS15169','asn_organization':'Google LLC'}]}, 'rdap': {'nameservers':['ns.example']},}, [{'provider':'OTX','state':'confirmed','reference':'pulse-1'}])
    assert len(graph['nodes']) == len({node['id'] for node in graph['nodes']})
    assert any(edge['relationship']=='resolves_to' for edge in graph['edges'])
    assert all(edge['evidence'] and edge['observed_at'] for edge in graph['edges'])
