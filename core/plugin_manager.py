"""Plugin system for custom rules and extensions"""
import os
import json
import time


from core.path_resolver import get_plugins_dir
PLUGINS_DIR = get_plugins_dir()

SUPPORTED_TYPES = ('tech_signature', 'security_payload', 'analysis_rule', 'sensitive_path')


class PluginManager:
    """Load and manage user-defined plugin rules"""

    def __init__(self):
        os.makedirs(PLUGINS_DIR, exist_ok=True)
        self._plugins = {}  # name -> plugin data
        self._disabled = set()  # disabled plugin names
        self.load_plugins()

    def load_plugins(self):
        """Scan plugins directory and load all JSON files"""
        self._plugins.clear()
        if not os.path.isdir(PLUGINS_DIR):
            return

        for fname in os.listdir(PLUGINS_DIR):
            if not fname.endswith('.json'):
                continue
            filepath = os.path.join(PLUGINS_DIR, fname)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if self._validate_plugin(data):
                    name = data['name']
                    data['_filename'] = fname
                    data['_filepath'] = filepath
                    self._plugins[name] = data
            except Exception as e:
                print(f'Plugin load error ({fname}): {e}')

    def _validate_plugin(self, data):
        """Validate plugin structure"""
        if not isinstance(data, dict):
            return False
        if 'name' not in data or 'type' not in data:
            return False
        if data['type'] not in SUPPORTED_TYPES:
            return False
        if 'rules' not in data or not isinstance(data['rules'], list):
            return False
        return True

    def list_plugins(self):
        """List all loaded plugins"""
        result = []
        for name, data in self._plugins.items():
            result.append({
                'name': name,
                'type': data.get('type', ''),
                'description': data.get('description', ''),
                'rules_count': len(data.get('rules', [])),
                'enabled': name not in self._disabled,
                'filename': data.get('_filename', ''),
            })
        return result

    def get_rules(self, plugin_type):
        """Get all rules of a specific type (built-in + plugins)"""
        rules = []
        for name, data in self._plugins.items():
            if name in self._disabled:
                continue
            if data.get('type') == plugin_type:
                rules.extend(data.get('rules', []))
        return rules

    def install(self, plugin_json):
        """Install a plugin from JSON string"""
        try:
            data = json.loads(plugin_json) if isinstance(plugin_json, str) else plugin_json
        except json.JSONDecodeError:
            return False, 'Invalid JSON'

        if not self._validate_plugin(data):
            return False, 'Invalid plugin format: requires name, type (tech_signature/security_payload/analysis_rule/sensitive_path), and rules array'

        name = data['name']
        filename = f'{name.lower().replace(" ", "_")}.json'
        filepath = os.path.join(PLUGINS_DIR, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            data['_filename'] = filename
            data['_filepath'] = filepath
            self._plugins[name] = data
            return True, f'Plugin "{name}" installed'
        except Exception as e:
            return False, f'Install failed: {e}'

    def toggle(self, name):
        """Enable/disable a plugin"""
        if name not in self._plugins:
            return False, 'Plugin not found'

        if name in self._disabled:
            self._disabled.discard(name)
            return True, f'Plugin "{name}" enabled'
        else:
            self._disabled.add(name)
            return True, f'Plugin "{name}" disabled'

    def uninstall(self, name):
        """Remove a plugin"""
        if name not in self._plugins:
            return False, 'Plugin not found'

        data = self._plugins.pop(name)
        self._disabled.discard(name)

        filepath = data.get('_filepath', '')
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass

        return True, f'Plugin "{name}" removed'

    def get_example(self):
        """Return an example plugin for reference"""
        return {
            'name': 'Example Tech Fingerprint',
            'type': 'tech_signature',
            'description': 'Example plugin showing the expected format',
            'rules': [
                {
                    'name': 'MyCMS',
                    'category': 'CMS',
                    'headers': {'X-Powered-By': 'MyCMS'},
                    'html': ['mycms-logo', 'data-mycms'],
                    'cookies': ['mycms_session'],
                },
                {
                    'name': 'MyFramework',
                    'category': 'Frontend',
                    'html': ['myframework.min.js', 'data-mf-component'],
                },
            ],
        }
