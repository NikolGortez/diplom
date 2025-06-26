// main.js

// 1) Подгружаем переменные из .env (PORT, NODE_ENV и т.п.)
require('dotenv').config();

const { app, BrowserWindow } = require('electron');
const path = require('path');
const isDev = process.env.NODE_ENV !== 'production';

let serverProcess = null;

// 2) В режиме разработки запускаем сервер автоматически
//if (isDev) {
  //const { spawn } = require('child_process');
 // const serverPath = path.join(__dirname, 'server', 'index.js');
//  serverProcess = spawn(
//    process.execPath, // тот же node.exe
//    [serverPath],
//    { stdio: 'inherit' }
//  );
//}

// 3) Функция создания окна
function createWindow() {
  const win = new BrowserWindow({
    width: 1024,
    height: 768,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // URL берём из переменной окружения или дефолтно 3001
  const port = process.env.PORT || 3001;
  const indexURL = `http://localhost:${port}`;

   win.loadURL('http://localhost:3000');
  // win.webContents.openDevTools(); // если нужно
win.on('closed', () => app.quit());
}

// 4) Ждём, когда Electron готов, и создаём окно
app.whenReady().then(createWindow);

// 5) На macOS принято пересоздавать окно при клике по иконке
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// 6) Корректно выходим + убиваем сервер, если он был запущен
app.on('window-all-closed', () => {
  if (serverProcess) {
    serverProcess.kill();
    serverProcess = null;
  }
  // На Windows и Linux полностью выходим
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
