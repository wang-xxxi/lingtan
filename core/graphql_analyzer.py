"""GraphQL introspection and schema analysis"""
import re
import json
import requests


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { kind name ofType { kind name ofType { kind name } } }
          defaultValue
        }
        type { kind name ofType { kind name ofType { kind name } } }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type { kind name ofType { kind name ofType { kind name } } }
        defaultValue
      }
      interfaces {
        kind name ofType { kind name ofType { kind name } }
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        kind name ofType { kind name ofType { kind name } }
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type { kind name ofType { kind name ofType { kind name } } }
        defaultValue
      }
    }
  }
}
"""

GRAPHQL_PATTERNS = [
    r'https?://[^\s"\'<>]+/graphql[/\w]*',
    r'https?://[^\s"\'<>]+/graphiql[/\w]*',
    r'https?://[^\s"\'<>]+/gql[/\w]*',
    r'https?://[^\s"\'<>]+/query[/\w]*',
    r'https?://[^\s"\'<>]+/api/graphql',
    r'/graphql["\']',
    r'/graphiql["\']',
    r'/gql["\']',
    r'graphqlEndpoint["\s:=]+["\']([^"\']+)',
    r'GRAPHQL_URL["\s:=]+["\']([^"\']+)',
]


class GraphQLAnalyzer:
    """Analyze GraphQL endpoints"""

    def introspect(self, url, headers=None):
        """Execute introspection query against a GraphQL endpoint"""
        hdrs = {'Content-Type': 'application/json'}
        if headers:
            hdrs.update(headers)

        try:
            resp = requests.post(
                url,
                json={'query': INTROSPECTION_QUERY},
                headers=hdrs,
                timeout=15,
                verify=False,
            )
            data = resp.json()
            if 'errors' in data and not data.get('data'):
                return {'error': data['errors'][0].get('message', 'Introspection failed'), 'schema': None}
            if 'data' in data and data['data'].get('__schema'):
                schema = data['data']['__schema']
                analysis = self.analyze_schema(schema)
                return {'error': None, 'schema': schema, 'analysis': analysis}
            return {'error': 'Unexpected response format', 'schema': None}
        except requests.exceptions.ConnectionError:
            return {'error': 'Connection failed', 'schema': None}
        except Exception as e:
            return {'error': str(e), 'schema': None}

    def analyze_schema(self, schema):
        """Parse schema into structured summary"""
        types = schema.get('types', [])
        result = {
            'queries': [],
            'mutations': [],
            'subscriptions': [],
            'types': [],
            'enums': [],
            'input_types': [],
            'scalars': [],
            'directives': [],
        }

        # Get root type names
        query_type = (schema.get('queryType') or {}).get('name')
        mutation_type = (schema.get('mutationType') or {}).get('name')
        subscription_type = (schema.get('subscriptionType') or {}).get('name')

        type_map = {}
        for t in types:
            name = t.get('name', '')
            if name.startswith('__'):
                continue
            kind = t.get('kind', '')
            type_map[name] = t

            if kind == 'OBJECT':
                fields_list = []
                for f in (t.get('fields') or []):
                    fields_list.append({
                        'name': f['name'],
                        'args': len(f.get('args', [])),
                        'type': self._type_name(f.get('type')),
                        'deprecated': f.get('isDeprecated', False),
                    })

                if name == query_type:
                    result['queries'] = fields_list
                elif name == mutation_type:
                    result['mutations'] = fields_list
                elif name == subscription_type:
                    result['subscriptions'] = fields_list
                else:
                    result['types'].append({
                        'name': name,
                        'kind': kind,
                        'fields': fields_list,
                        'description': t.get('description', ''),
                    })
            elif kind == 'ENUM':
                result['enums'].append({
                    'name': name,
                    'values': [ev['name'] for ev in (t.get('enumValues') or [])],
                })
            elif kind == 'INPUT_OBJECT':
                result['input_types'].append({
                    'name': name,
                    'fields': [{'name': f['name'], 'type': self._type_name(f.get('type'))}
                               for f in (t.get('inputFields') or [])],
                })
            elif kind == 'SCALAR':
                result['scalars'].append(name)

        for d in (schema.get('directives') or []):
            result['directives'].append({
                'name': d['name'],
                'locations': d.get('locations', []),
            })

        result['total_types'] = len(types) - sum(1 for t in types if (t.get('name') or '').startswith('__'))
        return result

    def _type_name(self, type_obj):
        """Extract readable type name from nested type structure"""
        if not type_obj:
            return 'Unknown'
        kind = type_obj.get('kind', '')
        name = type_obj.get('name', '')
        of_type = type_obj.get('ofType')

        if kind == 'NON_NULL':
            return f'{self._type_name(of_type)}!'
        elif kind == 'LIST':
            return f'[{self._type_name(of_type)}]'
        elif name:
            return name
        elif of_type:
            return self._type_name(of_type)
        return 'Unknown'

    def find_endpoints(self, html='', js_code=''):
        """Find potential GraphQL endpoints from HTML/JS content"""
        combined = f'{html}\n{js_code}'
        endpoints = set()

        for pattern in GRAPHQL_PATTERNS:
            try:
                matches = re.findall(pattern, combined, re.IGNORECASE)
                for m in matches:
                    m = m.strip().strip('"\'')
                    if m and len(m) < 500:
                        endpoints.add(m)
            except Exception:
                pass

        return list(endpoints)

    def generate_curl(self, endpoint, query=None):
        """Generate cURL command for GraphQL query"""
        q = query or '{ __typename }'
        escaped_q = json.dumps(q)
        return f'curl -X POST {endpoint} \\\n  -H "Content-Type: application/json" \\\n  -d \'{{"query": {escaped_q}}}\''
