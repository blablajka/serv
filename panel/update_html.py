import sys
import re

with open('d:/web_panel_for_vpn/smart_vpn/panel/static/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add Navigation Button
nav_btn = '<button class="nav-btn" :class="{active: tab===\'diagnostics\'}" @click="tab=\'diagnostics\'">Диагностика</button>'
new_nav_btn = nav_btn + '\n            <button class="nav-btn" :class="{active: tab===\'settings\'}" @click="fetchSettings(); tab=\'settings\'">⚙️ Настройки</button>'
content = content.replace(nav_btn, new_nav_btn)

# 2. Add Settings Tab Content
settings_tab = '''
    <!-- ══════════ SETTINGS TAB ══════════ -->
    <div v-show="tab==='settings'">
        <div class="row-between" style="margin-bottom: 20px;">
            <h2 style="font-size:18px;font-weight:700;">Глобальные настройки</h2>
        </div>
        
        <div class="card" style="max-width: 600px;">
            <div class="form-group">
                <label class="form-label">Domain / IP</label>
                <input class="form-input" v-model="settingsForm.domain" placeholder="example.com">
                <div style="font-size: 10px; color: var(--muted); margin-top: 4px;">Основной домен или IP адрес сервера для генерации ссылок</div>
            </div>
            
            <div class="form-group">
                <label class="form-label">XHTTP Path</label>
                <input class="form-input" v-model="settingsForm.xhttp_path" placeholder="/api/v1/stream/">
                <div style="font-size: 10px; color: var(--muted); margin-top: 4px;">Путь для маскировки трафика (начинается с /)</div>
            </div>
            
            <div class="form-group">
                <label class="form-label">Reality Server Names (SNI)</label>
                <input class="form-input" v-model="settingsForm.reality_server_names" placeholder="github.com">
                <div style="font-size: 10px; color: var(--muted); margin-top: 4px;">Домен для маскировки (тот самый "Идеальный домен" из сканера)</div>
            </div>

            <button class="btn btn-primary" style="width:100%; justify-content:center; margin-top: 10px;" @click="saveSettings" :disabled="settingsSaving">
                {{ settingsSaving ? '⏳ Сохранение и перезапуск...' : '💾 Сохранить и применить' }}
            </button>
            <div v-if="settingsSuccess" style="margin-top: 10px; color: var(--green); font-size: 12px; text-align: center;">✅ Настройки успешно применены!</div>
        </div>
    </div>
'''

diag_tab = '    <!-- ══════════ DIAGNOSTICS TAB ══════════ -->'
content = content.replace(diag_tab, settings_tab + '\n' + diag_tab)

# 3. Add Vue state and methods
vue_state = "const diagLoading   = ref(false);"
new_vue_state = vue_state + '''
        const settingsForm  = ref({ domain: '', xhttp_path: '', reality_server_names: '' });
        const settingsSaving = ref(false);
        const settingsSuccess = ref(false);
'''
content = content.replace(vue_state, new_vue_state)

vue_methods = "const fetchClients = async () => {"
new_vue_methods = '''
        const fetchSettings = async () => {
            try {
                const r = await fetch('/api/settings');
                const d = await r.json();
                settingsForm.value.domain = d.domain || '';
                settingsForm.value.xhttp_path = d.xhttp_path || '';
                settingsForm.value.reality_server_names = (d.reality_server_names && d.reality_server_names[0]) || '';
            } catch (e) { console.error('Failed to fetch settings', e); }
        };

        const saveSettings = async () => {
            settingsSaving.value = true;
            settingsSuccess.value = false;
            try {
                const res = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settingsForm.value)
                });
                if (res.ok) {
                    settingsSuccess.value = true;
                    setTimeout(() => settingsSuccess.value = false, 3000);
                } else {
                    const error = await res.json();
                    alert('Ошибка: ' + (error.error || 'Неизвестная ошибка'));
                }
            } catch (e) {
                alert('Ошибка сети: ' + e.message);
            } finally {
                settingsSaving.value = false;
            }
        };

''' + vue_methods
content = content.replace(vue_methods, new_vue_methods)


vue_return = "return {"
new_vue_return = vue_return + '''
            settingsForm, settingsSaving, settingsSuccess, fetchSettings, saveSettings,'''
content = content.replace(vue_return, new_vue_return)

with open('d:/web_panel_for_vpn/smart_vpn/panel/static/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('index.html updated successfully')
