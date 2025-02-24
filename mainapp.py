import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.slider import Slider
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import socket

kivy.require('2.0.0')  # Ensure the correct Kivy version is used

# AES декодирование
def decrypt_data(data, secret_key):
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8')

# Интерфейс для ввода данных
class SettingsPopup(Popup):
    def __init__(self, **kwargs):
        super(SettingsPopup, self).__init__(**kwargs)
        self.title = 'Settings'
        self.size_hint = (0.7, 0.4)
        layout = BoxLayout(orientation='vertical')

        # IP адрес
        self.ip_input = TextInput(hint_text="Enter server IP", multiline=False)
        layout.add_widget(self.ip_input)

        # AES пароль
        self.password_input = TextInput(hint_text="Enter AES password", multiline=False, password=True)
        layout.add_widget(self.password_input)

        # Кнопка сохранить
        save_button = Button(text="Save", size_hint=(1, 0.2))
        save_button.bind(on_press=self.save_settings)
        layout.add_widget(save_button)

        self.add_widget(layout)

    def save_settings(self, instance):
        ip = self.ip_input.text
        password = self.password_input.text
        App.get_running_app().update_settings(ip, password)
        self.dismiss()

class StatsApp(App):
    def build(self):
        self.settings = {'ip': '192.168.1.1', 'password': 'your_password'}
        self.root = BoxLayout(orientation='vertical')

        # Кнопка настроек
        settings_button = Button(text="Settings", size_hint=(1, 0.1))
        settings_button.bind(on_press=self.open_settings)
        self.root.add_widget(settings_button)

        # Статистика
        self.stats_layout = GridLayout(cols=1, padding=10, spacing=10)
        self.scrollview = ScrollView()
        self.scrollview.add_widget(self.stats_layout)
        self.root.add_widget(self.scrollview)

        # Получение статистики с сервера
        self.get_stats()

        return self.root

    def open_settings(self, instance):
        SettingsPopup().open()

    def update_settings(self, ip, password):
        self.settings['ip'] = ip
        self.settings['password'] = password

    def get_stats(self):
        # Здесь код для получения статистики с сервера
        # Примерный запрос к серверу:
        ip = self.settings['ip']
        port = 59999  # Порт для получения данных
        secret_key = self.settings['password'].encode('utf-8')

        # Установление соединения и получение зашифрованных данных
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(b'GET_STATS', (ip, port))
            data, _ = s.recvfrom(1024)
        
        try:
            decrypted_data = decrypt_data(data, secret_key)
            stats = json.loads(decrypted_data)

            # Обновление UI с полученной статистикой
            self.update_ui(stats)

        except Exception as e:
            print(f"Ошибка при получении данных: {e}")
            self.show_error("Failed to retrieve stats.")

    def update_ui(self, stats):
        self.stats_layout.clear_widgets()

        # Добавление информации о процессоре
        cpu_label = Label(text=f"CPU Usage: {stats['cpu_usage']}%", size_hint_y=None, height=40)
        self.stats_layout.add_widget(cpu_label)
        cpu_slider = Slider(min=0, max=100, value=stats['cpu_usage'], size_hint_y=None, height=40)
        self.stats_layout.add_widget(cpu_slider)

        # Добавление информации о памяти
        memory_label = Label(text=f"Memory Usage: {stats['memory']['used'] / 1024 ** 3:.2f} GB / {stats['memory']['total'] / 1024 ** 3:.2f} GB", size_hint_y=None, height=40)
        self.stats_layout.add_widget(memory_label)
        memory_slider = Slider(min=0, max=100, value=(stats['memory']['used'] / stats['memory']['total']) * 100, size_hint_y=None, height=40)
        self.stats_layout.add_widget(memory_slider)

        # Добавление информации о диске
        disk_label = Label(text=f"Disk Usage: {stats['disk']['used'] / 1024 ** 3:.2f} GB / {stats['disk']['total'] / 1024 ** 3:.2f} GB", size_hint_y=None, height=40)
        self.stats_layout.add_widget(disk_label)
        disk_slider = Slider(min=0, max=100, value=(stats['disk']['used'] / stats['disk']['total']) * 100, size_hint_y=None, height=40)
        self.stats_layout.add_widget(disk_slider)

        # Количество процессов
        processes_label = Label(text=f"Processes: {stats['processes']}", size_hint_y=None, height=40)
        self.stats_layout.add_widget(processes_label)

        # Сетевой трафик
        network_label = Label(text=f"Network (Incoming/Outgoing): {stats['network']['incoming']} / {stats['network']['outgoing']}", size_hint_y=None, height=40)
        self.stats_layout.add_widget(network_label)

    def show_error(self, message):
        error_popup = Popup(title="Error", content=Label(text=message), size_hint=(0.7, 0.4))
        error_popup.open()

if __name__ == '__main__':
    StatsApp().run()
