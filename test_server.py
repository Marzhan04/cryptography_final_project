from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return '<h1>✅ СЕРВЕР РАБОТАЕТ!</h1><p>Откройте <a href="/dashboard">панель управления</a></p>'

@app.route('/dashboard')
def dashboard():
    return '''
    <h1>Панель управления CryptoVault</h1>
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 30px;">
        <div style="border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
            <h3>🔐 Модуль 1</h3>
            <p>Аутентификация</p>
            <a href="/register">Регистрация</a>
        </div>
        <div style="border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
            <h3>✉️ Модуль 2</h3>
            <p>Сообщения</p>
            <a href="/send">Отправить</a>
        </div>
        <div style="border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
            <h3>📁 Модуль 3</h3>
            <p>Файлы</p>
            <a href="/encrypt">Шифровать</a>
        </div>
        <div style="border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
            <h3>⛓️ Модуль 4</h3>
            <p>Блокчейн</p>
            <a href="http://localhost:8000" target="_blank">Открыть</a>
        </div>
    </div>
    '''

if __name__ == '__main__':
    print("✅ Сервер запускается на http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
    