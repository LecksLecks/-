/* ================================================================================
   BARBER STYLE — BACKEND (Google Apps Script)
   Версия: 5.0 — 7 новых функций
   
   ИСПРАВЛЕНИЯ v4.0:
   FIX-01  BOT_TOKEN и OWNER_CHAT_ID вынесены в ScriptProperties
   FIX-02  ADMIN_CHAT_IDS читается из листа Users, не захардкожен
   FIX-03  getMasterNameById / getMasterIdByName читают лист Masters, не константу
   FIX-04  Добавлена колонка ReminderStatus в Bookings (16-я), Notes осталась (15-я)
   FIX-05  ensureSheetsExist убран из хот-пути doGet/doPost
   FIX-06  getAllMastersSlots кэшируется через CacheService (60 сек)
   FIX-07  Уведомления мастеру при новой/отменённой записи
   FIX-08  total передаётся числом — parseAmount вызывается сразу на входе
   FIX-09  HMAC-валидация initData Telegram (validateTelegramInitData)
   FIX-10  Статус reminder разделён: колонка 15 = Notes, колонка 16 = ReminderStatus
   NEW-01  Автобэкап таблицы раз в сутки
   NEW-02  Защита от спама (honeypot, временной анализ, blocklist)
   NEW-03  Средний чек и LTV клиента
   NEW-04  Потерянные клиенты — уведомление через 20 дней
   NEW-05  Массовая рассылка всем клиентам
   NEW-06  Благодарность через 2 часа после визита + просьба отзыва
   NEW-07  Поздравление с днём рождения + скидка 20%
   ================================================================================ */

// ─────────────────────────────────────────────────────────────────────────────
// КОНСТАНТЫ
// ─────────────────────────────────────────────────────────────────────────────
var CONFIG = {
  LOCK_DURATION_MS: 12000,
  RATE_LIMIT_COUNT: 3,
  RATE_LIMIT_HOURS: 1,
  REMINDER_MIN_HOURS: 1.5,
  REMINDER_MAX_HOURS: 2.5,
  MAX_NAME_LENGTH: 50,
  MIN_NAME_LENGTH: 2,
  MAX_TEXT_LENGTH: 1000,
  MIN_TEXT_LENGTH: 10,
  MAX_PHONE_LENGTH: 20,
  MAX_TELEGRAM_LENGTH: 100,
  REVIEWS_PER_PAGE: 20,
  SLOTS_CACHE_SECONDS: 60
};

// ─────────────────────────────────────────────────────────────────────────────
// FIX-01: НАСТРОЙКИ — читаются из ScriptProperties, не захардкожены
// Установить через: Файл → Свойства проекта → Свойства скрипта
//   BOT_TOKEN       = ваш токен бота
//   OWNER_CHAT_ID   = chat_id владельца
//   SPREADSHEET_ID  = id таблицы
//   ADMIN_INIT_KEY  = секретный ключ для initDb
// ─────────────────────────────────────────────────────────────────────────────
function getProps() {
  return PropertiesService.getScriptProperties().getProperties();
}

function BOT_TOKEN() {
  return getProps().BOT_TOKEN || '';
}

function OWNER_CHAT_ID() {
  return getProps().OWNER_CHAT_ID || '';
}

function SPREADSHEET_ID() {
  return getProps().SPREADSHEET_ID || '';
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX-02: ADMIN_CHAT_IDS читается из листа Users
// ─────────────────────────────────────────────────────────────────────────────
function getAdminChatIds() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var usersSheet = ss.getSheetByName('Users');
    if (!usersSheet || usersSheet.getLastRow() < 2) return [];
    var data = usersSheet.getDataRange().getValues();
    var admins = [];
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][1]).toLowerCase() === 'admin') {
        admins.push(String(data[i][0]));
      }
    }
    return admins;
  } catch (e) {
    return [];
  }
}

function isAdmin(chatId) {
  return getAdminChatIds().indexOf(String(chatId)) !== -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX-03: МАСТЕРА — читаются из листа Masters, не из константы
// ─────────────────────────────────────────────────────────────────────────────
function getMastersList() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var sheet = ss.getSheetByName('Masters');
    if (!sheet || sheet.getLastRow() < 2) return [];
    var data = sheet.getDataRange().getValues();
    var list = [];
    for (var i = 1; i < data.length; i++) {
      var active = data[i][4];
      if (active === false || String(active).toLowerCase() === 'false') continue;
      list.push({
        id:    parseInt(data[i][0]),
        name:  String(data[i][1] || ''),
        spec:  String(data[i][2] || ''),
        photo: String(data[i][3] || '')
      });
    }
    return list;
  } catch (e) {
    return [];
  }
}

function getMasterNameById(id) {
  var masters = getMastersList();
  for (var i = 0; i < masters.length; i++) {
    if (parseInt(masters[i].id) === parseInt(id)) return masters[i].name;
  }
  return null;
}

function getMasterIdByName(name) {
  var masters = getMastersList();
  for (var i = 0; i < masters.length; i++) {
    if (masters[i].name === name) return masters[i].id;
  }
  return null;
}

/* ================================================================================
   FIX-09: ВАЛИДАЦИЯ TELEGRAM initData (HMAC-SHA256)
   Передавать с фронта: initData = encodeURIComponent(tg.initData)
   ================================================================================ */
function validateTelegramInitData(initData) {
  try {
    if (!initData) return false;
    var token = BOT_TOKEN();
    if (!token) return false;

    var decoded = decodeURIComponent(initData);
    var pairs = decoded.split('&');
    var hash = '';
    var checkPairs = [];

    for (var i = 0; i < pairs.length; i++) {
      var kv = pairs[i].split('=');
      var k = kv[0];
      var v = pairs[i].substring(k.length + 1);
      if (k === 'hash') {
        hash = v;
      } else {
        checkPairs.push(k + '=' + decodeURIComponent(v));
      }
    }

    if (!hash) return false;
    checkPairs.sort();
    var dataCheckString = checkPairs.join('\n');

    var secretKey = Utilities.computeHmacSha256Signature(
      Utilities.newBlob(token).getBytes(),
      Utilities.newBlob('WebAppData').getBytes()
    );

    var computedHash = Utilities.computeHmacSha256Signature(
      Utilities.newBlob(dataCheckString).getBytes(),
      secretKey
    );

    var computedHex = computedHash.map(function(b) {
      return ('0' + (b & 0xff).toString(16)).slice(-2);
    }).join('');

    return computedHex === hash;
  } catch (e) {
    Logger.log('validateTelegramInitData error: ' + e.toString());
    return false;
  }
}

/* ================================================================================
   ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
   ================================================================================ */

function sanitizeHtml(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function validateField(value, minLength, maxLength, fieldName) {
  if (!value || typeof value !== 'string') {
    return { valid: false, error: fieldName + ' не указан' };
  }
  var trimmed = value.trim();
  if (trimmed.length < minLength) {
    return { valid: false, error: fieldName + ' должен содержать минимум ' + minLength + ' символов' };
  }
  if (trimmed.length > maxLength) {
    return { valid: false, error: fieldName + ' не должен превышать ' + maxLength + ' символов' };
  }
  return { valid: true, value: trimmed };
}

function convertTimeToString(value) {
  if (!value) return '';
  if (value instanceof Date) {
    var hours = value.getHours();
    var minutes = value.getMinutes();
    return String(hours).padStart(2, '0') + ':' + String(minutes).padStart(2, '0');
  }
  if (typeof value === 'string') {
    if (value.indexOf('T') !== -1) {
      var d = new Date(value);
      if (!isNaN(d.getTime())) {
        return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
      }
    }
    if (value.startsWith("'")) value = value.substring(1);
    return value;
  }
  return String(value);
}

function convertDateToString(value) {
  if (!value) return '';
  if (value instanceof Date) {
    return value.getFullYear() + '-' +
      String(value.getMonth() + 1).padStart(2, '0') + '-' +
      String(value.getDate()).padStart(2, '0');
  }
  if (typeof value === 'string') {
    if (value.indexOf('T') !== -1) {
      var d = new Date(value);
      if (!isNaN(d.getTime())) {
        return d.getFullYear() + '-' +
          String(d.getMonth() + 1).padStart(2, '0') + '-' +
          String(d.getDate()).padStart(2, '0');
      }
    }
    if (value.startsWith("'")) value = value.substring(1);
    return value;
  }
  return String(value);
}

function formatDateTimeForDisplay(dateValue, timeValue) {
  var dateStr = convertDateToString(dateValue);
  var timeStr = convertTimeToString(timeValue);
  if (!dateStr) return '';
  var parts = dateStr.split('-');
  var day = parseInt(parts[2]);
  var monthNames = ['января','февраля','марта','апреля','мая','июня',
                    'июля','августа','сентября','октября','ноября','декабря'];
  var month = monthNames[parseInt(parts[1]) - 1];
  var year = parts[0];
  var result = day + ' ' + month + ' ' + year;
  if (timeStr) result += ', ' + timeStr;
  return result;
}

function formatDateRu(date, format) {
  if (!date) return '';
  var d;
  if (typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
    var p = date.split('-');
    d = new Date(parseInt(p[0]), parseInt(p[1]) - 1, parseInt(p[2]));
  } else {
    d = new Date(date);
  }
  var months = ['января','февраля','марта','апреля','мая','июня',
                'июля','августа','сентября','октября','ноября','декабря'];
  var day = d.getDate();
  var month = months[d.getMonth()];
  var year = d.getFullYear();
  return format === 'full' ? (day + ' ' + month + ' ' + year) : (day + ' ' + month);
}

function formatDateIso(date) {
  var d = date instanceof Date ? date : new Date(date);
  return d.getFullYear() + '-' +
    String(d.getMonth() + 1).padStart(2, '0') + '-' +
    String(d.getDate()).padStart(2, '0');
}

// Очищает телефон от #ERROR!, апострофов и формул Google Sheets
function cleanPhoneValue(value) {
  if (!value) return '';
  var s = String(value).trim();
  if (s.indexOf('#') === 0 || s.indexOf('=') === 0) return '';
  if (s.indexOf("'") === 0) s = s.substring(1);
  return s;
}

function parseAmount(value) {
  if (!value) return 0;
  if (typeof value === 'number') return value;
  var str = String(value).replace(/[^\d.-]/g, '');
  var num = parseFloat(str);
  return isNaN(num) ? 0 : num;
}

/* ================================================================================
   АВТОМАТИЧЕСКОЕ СОЗДАНИЕ БАЗЫ ДАННЫХ
   ================================================================================ */

function initializeDatabase() {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());

  var sheetsConfig = {
    'Bookings': {
      // FIX-04: добавлена колонка ReminderStatus (16-я)
      headers: ['CreatedAt','BookingId','Master','MasterId','DateDisplay','DateRaw','Time',
                'Name','Phone','Telegram','Services','Total','ChatId','Status','Notes','ReminderStatus'],
      widths:  [120,80,100,60,120,100,60,120,100,100,200,60,100,80,100,100]
    },
    'Clients': {
      headers: ['ChatId','Name','Phone','Telegram','FirstVisit','LastVisit','TotalBookings','TotalSpent','Birthday'],
      widths:  [100,120,100,100,100,100,80,80,100]
    },
    'Blocks': {
      headers: ['Master','MasterId','Date','Time','CreatedAt','Reason'],
      widths:  [100,60,100,60,120,150]
    },
    'DayOffs': {
      headers: ['Master','MasterId','Date','CreatedAt','Note'],
      widths:  [100,60,100,120,150]
    },
    'Reviews': {
      headers: ['Name','Text','Rating','Date','ChatId','Master'],
      widths:  [100,300,60,100,100,100]
    },
    'Users': {
      headers: ['ChatId','Role','MasterId','MasterName','CreatedAt'],
      widths:  [100,80,60,100,120]
    },
    'Masters': {
      headers: ['Id','Name','Spec','Photo','Active','CreatedAt'],
      widths:  [40,100,150,200,60,100],
      defaultData: [
        [0,'Саркис','Стрижки и фейды','',true,new Date()],
        [1,'Лиза','Мужские стрижки','',true,new Date()],
        [2,'Нарек','Современные техники','',true,new Date()],
        [3,'Миша','Оформление бороды','',true,new Date()],
        [4,'Рустам','Фейды','',true,new Date()],
        [5,'Милена','Уходовые процедуры','',true,new Date()],
        [6,'Никита','Классические стрижки','',true,new Date()]
      ]
    },
    'Settings': {
      headers: ['Key','Value','Description'],
      widths:  [100,200,300],
      defaultData: [
        ['workStart','09:00','Начало рабочего дня'],
        ['workEnd','21:00','Конец рабочего дня'],
        ['slotDuration','60','Длительность слота в минутах'],
        ['currency','₽','Валюта'],
        ['address','г. Батайск, ул. Октябрьская, 108','Адрес'],
        ['phone','+7 (952) 560-88-98','Телефон'],
        ['timezone','Europe/Moscow','Часовой пояс']
      ]
    },
    'Prices': {
      headers: ['Category','Name','Price','Active'],
      widths:  [80,250,80,60],
      defaultData: [
        ['head','Насадка (триммер) 1–2',500,true],
        ['head','Удлинённая стрижка',1300,true],
        ['head','Стрижка',1000,true],
        ['head','Укладка',300,true],
        ['head','Шейвер',600,true],
        ['head','Рисунок',400,true],
        ['head','Тонировка',1000,true],
        ['head','Королевское бритьё + скрабирование',1000,true],
        ['head','Окантовка',200,true],
        ['head','Тонировка бровей',100,true],
        ['face','Шейвер',600,true],
        ['face','Насадка (триммер)',300,true],
        ['face','Тонировка',900,true],
        ['face','Королевское бритьё + скрабирование',1000,true],
        ['face','Оформление бороды',800,true],
        ['face','Чёрная маска',400,true],
        ['face','Скраб',300,true],
        ['wax','Коррекция бровей',300,true],
        ['wax','Уши или нос',200,true],
        ['wax','Кончик носа',100,true],
        ['wax','Между бровями',100,true],
        ['wax','Виски в районе бровей',200,true],
        ['wax','Щёки',400,true],
        ['wax','Шея',500,true],
        ['wax','Кадык',500,true]
      ]
    }
  };

  try {
    var result = { success: true, spreadsheetId: ss.getId(), spreadsheetUrl: ss.getUrl(), sheets: [] };

    for (var sheetName in sheetsConfig) {
      var cfg = sheetsConfig[sheetName];
      var sheet = ss.getSheetByName(sheetName);
      if (!sheet) sheet = ss.insertSheet(sheetName);

      if (cfg.headers && cfg.headers.length > 0) {
        sheet.getRange(1, 1, 1, cfg.headers.length).setValues([cfg.headers]);
        var hr = sheet.getRange(1, 1, 1, cfg.headers.length);
        hr.setFontWeight('bold');
        hr.setBackground('#c9a84c');
        hr.setFontColor('#0a0805');
        hr.setHorizontalAlignment('center');
      }
      if (cfg.widths) {
        for (var i = 0; i < cfg.widths.length; i++) sheet.setColumnWidth(i + 1, cfg.widths[i]);
      }
      if (cfg.defaultData && sheet.getLastRow() < 2) {
        sheet.getRange(2, 1, cfg.defaultData.length, cfg.defaultData[0].length).setValues(cfg.defaultData);
      }
      sheet.setFrozenRows(1);
      result.sheets.push(sheetName);
    }

    ss.setSpreadsheetTimeZone('Europe/Moscow');
    Logger.log('✅ Инициализация завершена. URL: ' + ss.getUrl());
    return result;

  } catch (e) {
    Logger.log('❌ Ошибка: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/* FIX-05: ensureSheetsExist вызывается только при необходимости, не в хот-пути */
function sheetsExist() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var required = ['Bookings','Clients','Blocks','DayOffs','Reviews','Users','Masters','Prices'];
    for (var i = 0; i < required.length; i++) {
      if (!ss.getSheetByName(required[i])) return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

/* ================================================================================
   ДАННЫЕ ПРИЛОЖЕНИЯ
   ================================================================================ */

function getAppData() {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var mastersSheet = ss.getSheetByName('Masters');
  var pricesSheet  = ss.getSheetByName('Prices');
  var reviewsSheet = ss.getSheetByName('Reviews');

  var masters = [];
  if (mastersSheet && mastersSheet.getLastRow() > 1) {
    var mData = mastersSheet.getDataRange().getValues();
    for (var i = 1; i < mData.length; i++) {
      var active = mData[i][4];
      if (active === false || String(active).toLowerCase() === 'false') continue;
      masters.push({ id: parseInt(mData[i][0]) || 0, name: String(mData[i][1]||''), spec: String(mData[i][2]||''), photo: String(mData[i][3]||'') });
    }
  }

  var prices = {};
  if (pricesSheet && pricesSheet.getLastRow() > 1) {
    var pData = pricesSheet.getDataRange().getValues();
    for (var j = 1; j < pData.length; j++) {
      var pActive = pData[j][3];
      if (pActive === false || String(pActive).toLowerCase() === 'false') continue;
      var cat  = String(pData[j][0]||'').toLowerCase();
      var name = String(pData[j][1]||'');
      var price = parseFloat(pData[j][2]) || 0;
      if (!cat || !name) continue;
      if (!prices[cat]) prices[cat] = [];
      prices[cat].push([name, price]);
    }
  }

  var ratings = {};
  if (reviewsSheet && reviewsSheet.getLastRow() > 1) {
    var rData = reviewsSheet.getDataRange().getValues();
    for (var k = 1; k < rData.length; k++) {
      var masterName = String(rData[k][5]||'');
      var rating = parseFloat(rData[k][2]) || 0;
      if (!masterName || rating === 0) continue;
      if (!ratings[masterName]) ratings[masterName] = {sum:0, count:0};
      ratings[masterName].sum   += rating;
      ratings[masterName].count += 1;
    }
    for (var mn in ratings) {
      var r = ratings[mn];
      ratings[mn] = { avg: Math.round(r.sum / r.count * 10) / 10, count: r.count };
    }
  }

  return ContentService.createTextOutput(JSON.stringify({
    masters: masters.length > 0 ? masters : null,
    prices:  Object.keys(prices).length > 0 ? prices : null,
    ratings: ratings
  })).setMimeType(ContentService.MimeType.JSON);
}

/* ================================================================================
   ОБРАБОТЧИК GET ЗАПРОСОВ
   ================================================================================ */

function doGet(e) {
  var params = e.parameter;

  if (params.action === 'initDb') {
    var adminKey = PropertiesService.getScriptProperties().getProperty('ADMIN_INIT_KEY');
    if (!adminKey || params.adminKey !== adminKey) {
      return jsonOut({error: 'Unauthorized'});
    }
    return jsonOut(initializeDatabase());
  }

  if (params.action === 'status') {
    return jsonOut({ status: 'ok', version: '4.0', timestamp: new Date().toISOString() });
  }

  // FIX-05: проверка таблицы только один раз, не ensureSheetsExist
  if (!sheetsExist()) {
    return jsonOut({ error: 'Database not initialized', message: 'Call ?action=initDb first' });
  }

  if (params.action === 'getAppData')                            return getAppData();
  if (params.action === 'getUserInfo' && params.chatId)          return getUserInfo(params.chatId);
  if (params.action === 'getAllMastersSlots')                     return getAllMastersSlots();
  if (params.action === 'getMasterSchedule')                     return getMasterSchedule(params.masterId, params.date);
  if (params.action === 'getMyBookings' && params.chatId)        return getMyBookings(params.chatId);
  if (params.action === 'getMyBookingsHistory' && params.chatId) return getMyBookingsHistory(params.chatId);
  if (params.action === 'getBookings' && params.date && params.chatId) return getAdminBookings(params.date, params.masterId, params.chatId);
  if (params.action === 'blockSlot' || params.action === 'unblockSlot') return handleSlotAction(params);
  if (params.action === 'dayOff' || params.action === 'removeDayOff' || params.action === 'forceDayOff') return handleDayOff(params);
  if (params.action === 'getAllDayOffs' && params.chatId)        return getAllDayOffs(params.chatId);
  if (params.action === 'getReviews')                            return getReviews(parseInt(params.offset)||0, parseInt(params.limit)||CONFIG.REVIEWS_PER_PAGE);
  if (params.action === 'getAnalytics' && params.chatId)         return getAnalytics(params.chatId);
  if (params.action === 'getClients' && params.chatId)           return getClients(params.search, params.chatId);
  if (params.action === 'getClientsLTV' && params.chatId)      return getClientsWithLTV(params.search, params.chatId);
  if (params.action === 'broadcast')                             return broadcastMessage(params);
  if (params.action === 'blockUser')                             return handleBlockUser(params);
  if (params.action === 'getPromos')                                return getPromos();
  if (params.action === 'checkPromo' && params.code)           return jsonOut(checkPromoCode(params.code, params.chatId));

  return jsonOut({status: 'ok'});
}

/* ================================================================================
   ОБРАБОТЧИК POST ЗАПРОСОВ
   ================================================================================ */

function doPost(e) {
  var data;
  try {
    data = JSON.parse(e.postData.contents);
  } catch (err) {
    return jsonOut({error: 'Invalid JSON'});
  }

  if (data.callback_query) {
    doPost_confirmCallback(data.callback_query);
    return jsonOut({ok: true});
  }

  if (!sheetsExist()) {
    return jsonOut({error: 'Database not initialized'});
  }

  // Создание записи
  if (data.master && data.visitDate && data.time && data.name && data.phone) {
    var nameVal = validateField(data.name, CONFIG.MIN_NAME_LENGTH, CONFIG.MAX_NAME_LENGTH, 'Имя');
    if (!nameVal.valid) return jsonOut({error: nameVal.error});
    data.name = sanitizeHtml(nameVal.value);

    var phoneDigits = (data.phone || '').replace(/\D/g, '');
    if (phoneDigits.length < 10 || phoneDigits.length > 15) return jsonOut({error: 'Некорректный номер телефона'});

    if (data.telegram) {
      var tgVal = validateField(data.telegram, 1, CONFIG.MAX_TELEGRAM_LENGTH, 'Telegram');
      if (!tgVal.valid) return jsonOut({error: tgVal.error});
      data.telegram = sanitizeHtml(tgVal.value);
    }

    // NEW-02: проверка спама перед созданием записи
    var spamCheck = isSpam(data);
    if (spamCheck.spam) {
      Logger.log('SPAM blocked: ' + spamCheck.reason + ' from ' + (data.clientChatId || data.phone));
      return jsonOut({status: 'ok', bookingId: 'FAKE'}); // не сообщаем боту что заблокирован
    }

    // FIX-08: total сразу конвертируем в число
    data.total = parseAmount(data.total);
    data.services = sanitizeHtml(data.services || '');
    return createBooking(data);
  }

  if (data.action === 'cancelBooking') return cancelBooking(data);

  if (data.action === 'addReview') {
    var rName = validateField(data.name, CONFIG.MIN_NAME_LENGTH, CONFIG.MAX_NAME_LENGTH, 'Имя');
    if (!rName.valid) return jsonOut({error: rName.error});
    var rText = validateField(data.text, CONFIG.MIN_TEXT_LENGTH, CONFIG.MAX_TEXT_LENGTH, 'Текст отзыва');
    if (!rText.valid) return jsonOut({error: rText.error});
    data.name = sanitizeHtml(rName.value);
    data.text = sanitizeHtml(rText.value);
    if (!data.rating || data.rating < 1 || data.rating > 5) return jsonOut({error: 'Укажите оценку от 1 до 5'});
    return addReview(data);
  }

  return jsonOut({status: 'ok'});
}

/* ================================================================================
   ПОЛУЧЕНИЕ РОЛИ ПОЛЬЗОВАТЕЛЯ
   ================================================================================ */

function getUserInfo(chatId) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var usersSheet = ss.getSheetByName('Users');
  var role = 'client';
  var master = null;

  if (usersSheet) {
    var usersData = usersSheet.getDataRange().getValues();
    for (var i = 1; i < usersData.length; i++) {
      if (String(usersData[i][0]) === String(chatId)) {
        role = usersData[i][1] || 'client';
        if (role === 'master' && usersData[i][2] !== null && usersData[i][2] !== '') {
          master = { id: usersData[i][2], name: usersData[i][3] || getMasterNameById(usersData[i][2]) };
        }
        break;
      }
    }
  }

  // FIX-02: запасная проверка через динамический список
  if (role === 'client' && isAdmin(chatId)) role = 'admin';

  return jsonOut({ chatId: chatId, role: role, master: master });
}

/* ================================================================================
   СОЗДАНИЕ ЗАПИСИ
   ================================================================================ */

function createBooking(data) {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(CONFIG.LOCK_DURATION_MS);
  } catch (lockErr) {
    return jsonOut({ error: 'slot_taken', message: 'Сервер занят, попробуйте ещё раз' });
  }

  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var bookingsSheet = ss.getSheetByName('Bookings');
    var clientsSheet  = ss.getSheetByName('Clients');

    // Двойная запись
    if (data.clientChatId) {
      var existing = findClientBooking(data.clientChatId, data.visitDateRaw, data.time);
      if (existing) return jsonOut({ status: 'double_booking', error: 'У вас уже есть запись на это время', existingBooking: existing });
    }

    // Выходной
    var dayoffsSheet = ss.getSheetByName('DayOffs');
    if (dayoffsSheet && dayoffsSheet.getLastRow() > 1) {
      var doffs = dayoffsSheet.getDataRange().getValues();
      for (var k = 1; k < doffs.length; k++) {
        if (doffs[k][0] === data.master && convertDateToString(doffs[k][2]) === data.visitDateRaw) {
          return jsonOut({ error: 'dayoff', message: 'Выбранный день — выходной для мастера' });
        }
      }
    }

    // Слот занят
    if (checkSlotTaken(data.master, data.visitDateRaw, data.time)) {
      return jsonOut({ error: 'slot_taken' });
    }

    // Rate limit
    var rlKey = data.clientChatId ? 'rate_' + data.clientChatId : 'rate_phone_' + data.phone.replace(/\D/g,'');
    if (countRecentBookingsByKey(rlKey) >= CONFIG.RATE_LIMIT_COUNT) {
      return jsonOut({ status: 'rate_limit', error: 'Слишком много запросов. Попробуйте позже.' });
    }

    // Финальная проверка
    var bData = bookingsSheet.getDataRange().getValues();
    for (var i = 1; i < bData.length; i++) {
      if (bData[i][2] === data.master &&
          convertDateToString(bData[i][5]) === data.visitDateRaw &&
          convertTimeToString(bData[i][6]) === data.time &&
          bData[i][13] === 'confirmed') {
        return jsonOut({ error: 'slot_taken', message: 'Это время только что занял другой клиент' });
      }
    }

    var bookingId = Utilities.getUuid().substring(0, 8).toUpperCase();
    var masterId  = data.masterId !== undefined ? data.masterId : getMasterIdByName(data.master);

    // FIX-04: 16 колонок — Notes(15) и ReminderStatus(16)
    var rowData = [
      new Date(),
      bookingId,
      data.master,
      masterId,
      data.visitDate,
      "'" + data.visitDateRaw,
      "'" + data.time,
      data.name,
      data.phone,
      data.telegram || '',
      data.services,
      data.total,          // FIX-08: уже число
      String(data.clientChatId || ''),
      'confirmed',
      '',                  // Notes
      ''                   // ReminderStatus
    ];

    bookingsSheet.appendRow(rowData);
    updateClientProfile(clientsSheet, data);

    // FIX-06: инвалидируем кэш слотов
    CacheService.getScriptCache().remove('allMastersSlots');

    sendBookingNotifications(data, bookingId, masterId);

    return jsonOut({ status: 'ok', bookingId: bookingId });

  } catch (e) {
    Logger.log('createBooking error: ' + e.toString());
    return jsonOut({ error: 'Внутренняя ошибка сервера. Попробуйте позже.' });
  } finally {
    lock.releaseLock();
  }
}

/* ================================================================================
   FIX-06: getAllMastersSlots с кэшем CacheService
   ================================================================================ */

function getAllMastersSlots() {
  var cache = CacheService.getScriptCache();
  var cached = cache.get('allMastersSlots');
  if (cached) {
    return ContentService.createTextOutput(cached).setMimeType(ContentService.MimeType.JSON);
  }

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  var blocksSheet   = ss.getSheetByName('Blocks');
  var dayoffsSheet  = ss.getSheetByName('DayOffs');

  // FIX-03: список мастеров из таблицы
  var mastersList = getMastersList();
  var result = {};
  mastersList.forEach(function(m) {
    result[m.name] = { slots: {}, blocks: {}, dayoffs: [] };
  });

  if (bookingsSheet && bookingsSheet.getLastRow() > 1) {
    var bData = bookingsSheet.getDataRange().getValues();
    for (var i = 1; i < bData.length; i++) {
      var mn = bData[i][2];
      var dt = convertDateToString(bData[i][5]);
      var tm = convertTimeToString(bData[i][6]);
      if (result[mn] && bData[i][13] === 'confirmed') {
        if (!result[mn].slots[dt]) result[mn].slots[dt] = [];
        result[mn].slots[dt].push(tm);
      }
    }
  }

  if (blocksSheet && blocksSheet.getLastRow() > 1) {
    var blData = blocksSheet.getDataRange().getValues();
    for (var j = 1; j < blData.length; j++) {
      var mn2 = blData[j][0];
      var dt2 = convertDateToString(blData[j][2]);
      var tm2 = convertTimeToString(blData[j][3]);
      if (result[mn2]) {
        if (!result[mn2].blocks[dt2]) result[mn2].blocks[dt2] = [];
        result[mn2].blocks[dt2].push(tm2);
      }
    }
  }

  if (dayoffsSheet && dayoffsSheet.getLastRow() > 1) {
    var dData = dayoffsSheet.getDataRange().getValues();
    for (var k = 1; k < dData.length; k++) {
      var mn3 = dData[k][0];
      var dt3 = convertDateToString(dData[k][2]);
      if (result[mn3] && result[mn3].dayoffs.indexOf(dt3) === -1) {
        result[mn3].dayoffs.push(dt3);
      }
    }
  }

  var payload = JSON.stringify({ masters: result });
  cache.put('allMastersSlots', payload, CONFIG.SLOTS_CACHE_SECONDS);
  return ContentService.createTextOutput(payload).setMimeType(ContentService.MimeType.JSON);
}

function getMasterSchedule(masterId, date) {
  var masterName = getMasterNameById(masterId);
  if (!masterName) return jsonOut({ error: 'Master not found' });

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  var blocksSheet   = ss.getSheetByName('Blocks');
  var dayoffsSheet  = ss.getSheetByName('DayOffs');

  var booked = {}, blocked = {}, dayoffs = [];

  if (bookingsSheet && bookingsSheet.getLastRow() > 1) {
    var bData = bookingsSheet.getDataRange().getValues();
    for (var i = 1; i < bData.length; i++) {
      var isMatch = (bData[i][2] === masterName) ||
        (bData[i][3] !== undefined && parseInt(bData[i][3]) === parseInt(masterId));
      if (isMatch && bData[i][13] === 'confirmed') {
        var rd = convertDateToString(bData[i][5]);
        var rt = convertTimeToString(bData[i][6]);
        if (!booked[rd]) booked[rd] = [];
        booked[rd].push(rt);
      }
    }
  }

  if (blocksSheet && blocksSheet.getLastRow() > 1) {
    var blData = blocksSheet.getDataRange().getValues();
    for (var j = 1; j < blData.length; j++) {
      var isMatchBl = (blData[j][0] === masterName) ||
        (blData[j][1] !== undefined && parseInt(blData[j][1]) === parseInt(masterId));
      if (isMatchBl) {
        var bd = convertDateToString(blData[j][2]);
        var bt = convertTimeToString(blData[j][3]);
        if (!blocked[bd]) blocked[bd] = [];
        blocked[bd].push(bt);
      }
    }
  }

  if (dayoffsSheet && dayoffsSheet.getLastRow() > 1) {
    var dData = dayoffsSheet.getDataRange().getValues();
    for (var k = 1; k < dData.length; k++) {
      var isMatchD = (dData[k][0] === masterName) ||
        (dData[k][1] !== undefined && parseInt(dData[k][1]) === parseInt(masterId));
      if (isMatchD) dayoffs.push(convertDateToString(dData[k][2]));
    }
  }

  return jsonOut({ booked: booked, blocked: blocked, dayoffs: dayoffs });
}

/* ================================================================================
   RATE LIMITING
   ================================================================================ */

function countRecentBookingsByKey(key) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return 0;
  var data = bookingsSheet.getDataRange().getValues();
  var oneHourAgo = new Date(Date.now() - CONFIG.RATE_LIMIT_HOURS * 3600000);
  var count = 0;
  for (var i = data.length - 1; i >= 1; i--) {
    var rowKey = key.indexOf('rate_phone_') === 0
      ? 'rate_phone_' + String(data[i][8] || '').replace(/\D/g, '')
      : 'rate_' + String(data[i][12] || '');
    if (rowKey === key && new Date(data[i][0]) > oneHourAgo) count++;
  }
  return count;
}

/* ================================================================================
   ПОИСК И ОТМЕНА ЗАПИСЕЙ
   ================================================================================ */

function checkSlotTaken(master, date, time) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());

  var dayoffsSheet = ss.getSheetByName('DayOffs');
  if (dayoffsSheet && dayoffsSheet.getLastRow() > 1) {
    var dData = dayoffsSheet.getDataRange().getValues();
    for (var k = 1; k < dData.length; k++) {
      if (dData[k][0] === master && convertDateToString(dData[k][2]) === date) return true;
    }
  }

  var blocksSheet = ss.getSheetByName('Blocks');
  if (blocksSheet && blocksSheet.getLastRow() > 1) {
    var blData = blocksSheet.getDataRange().getValues();
    for (var j = 1; j < blData.length; j++) {
      if (blData[j][0] === master && convertDateToString(blData[j][2]) === date && convertTimeToString(blData[j][3]) === time) return true;
    }
  }

  var bookingsSheet = ss.getSheetByName('Bookings');
  if (bookingsSheet && bookingsSheet.getLastRow() > 1) {
    var bData = bookingsSheet.getDataRange().getValues();
    for (var i = 1; i < bData.length; i++) {
      if (bData[i][2] === master && convertDateToString(bData[i][5]) === date && convertTimeToString(bData[i][6]) === time && bData[i][13] === 'confirmed') return true;
    }
  }
  return false;
}

function findClientBooking(chatId, date, time) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return null;
  var data = bookingsSheet.getDataRange().getValues();
  chatId = String(chatId || '');
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][12]) === chatId &&
        convertDateToString(data[i][5]) === date &&
        convertTimeToString(data[i][6]) === time &&
        data[i][13] === 'confirmed') {
      return { master: data[i][2], masterId: data[i][3], date: convertDateToString(data[i][5]), time: convertTimeToString(data[i][6]) };
    }
  }
  return null;
}

function cancelBooking(data) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return jsonOut({error: 'Database error'});

  var bData = bookingsSheet.getDataRange().getValues();
  var reqChatId = String(data.chatId || '');
  var CANCEL_DEADLINE_HOURS = 2;

  for (var i = 1; i < bData.length; i++) {
    var rowDate   = convertDateToString(bData[i][5]);
    var rowTime   = convertTimeToString(bData[i][6]);
    var rowChatId = String(bData[i][12] || '');
    var rowMaster = bData[i][2];

    var masterMatch = (data.master && rowMaster === data.master) ||
      (data.masterId !== undefined && bData[i][3] !== undefined && parseInt(bData[i][3]) === parseInt(data.masterId));

    if (rowDate === data.date && rowTime === data.time && masterMatch && bData[i][13] === 'confirmed') {
      var isOwner = reqChatId && rowChatId === reqChatId;
      var admins  = isAdmin(reqChatId);

      if (!isOwner && !admins) {
        return jsonOut({ error: 'Unauthorized', message: 'У вас нет прав для отмены этой записи' });
      }

      if (isOwner && !admins) {
        var dp = rowDate.split('-');
        var tp = rowTime.split(':');
        var bookingDt = new Date(parseInt(dp[0]), parseInt(dp[1])-1, parseInt(dp[2]), parseInt(tp[0]), parseInt(tp[1]||0));
        var hoursUntil = (bookingDt - new Date()) / 3600000;
        if (hoursUntil >= 0 && hoursUntil < CANCEL_DEADLINE_HOURS) {
          return jsonOut({ error: 'too_late', message: 'Отмена доступна не позднее чем за ' + CANCEL_DEADLINE_HOURS + ' ч до визита. Позвоните: +7 (952) 560-88-98' });
        }
      }

      bookingsSheet.getRange(i + 1, 14).setValue('cancelled');

      // FIX-06: инвалидация кэша
      CacheService.getScriptCache().remove('allMastersSlots');

      sendTelegramMessageSafe(OWNER_CHAT_ID(), '❌ <b>Запись отменена</b>\n\n👤 ' + sanitizeHtml(bData[i][7]) + '\n📞 ' + bData[i][8] + '\n💇 ' + rowMaster + '\n📅 ' + rowDate + ' в ' + rowTime, {parse_mode:'HTML'});

      // FIX-07: уведомление мастеру
      notifyMasterAboutCancellation(bData[i][3] || getMasterIdByName(rowMaster), bData[i][7], rowDate, rowTime);

      return jsonOut({status: 'ok'});
    }
  }

  return jsonOut({error: 'Booking not found'});
}

/* ================================================================================
   МОИ ЗАПИСИ
   ================================================================================ */

function getMyBookings(chatId) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return jsonOut({bookings: []});

  chatId = String(chatId || '');
  var data = bookingsSheet.getDataRange().getValues();
  var result = [];
  var now = new Date();
  var todayStr = formatDateIso(now);
  var nowH = now.getHours(), nowM = now.getMinutes();

  for (var i = 1; i < data.length; i++) {
    if (String(data[i][12]) !== chatId || data[i][13] !== 'confirmed') continue;
    var rowDate = convertDateToString(data[i][5]);
    var rowTime = convertTimeToString(data[i][6]);
    var isFuture = false;
    if (rowDate > todayStr) {
      isFuture = true;
    } else if (rowDate === todayStr && rowTime) {
      var tp = rowTime.split(':');
      var rH = parseInt(tp[0])||0, rM = parseInt(tp[1])||0;
      if (rH > nowH || (rH === nowH && rM > nowM)) isFuture = true;
    }
    if (!isFuture) continue;

    var masterId = data[i][3];
    if (masterId === undefined || masterId === null || masterId === '') masterId = getMasterIdByName(data[i][2]);

    result.push({
      id:            data[i][1],
      master:        data[i][2],
      masterId:      masterId,
      date:          rowDate,
      dateFormatted: formatDateTimeForDisplay(data[i][5], data[i][6]),
      time:          rowTime,
      services:      data[i][10],
      total:         data[i][11]
    });
  }

  result.sort(function(a,b){ return a.date < b.date ? -1 : a.date > b.date ? 1 : a.time < b.time ? -1 : 1; });
  return jsonOut({bookings: result});
}

function getMyBookingsHistory(chatId) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return jsonOut({bookings: [], hasMore: false});

  chatId = String(chatId || '');
  var data = bookingsSheet.getDataRange().getValues();
  var result = [];
  var now = new Date();
  var todayStr = formatDateIso(now);
  var nowH = now.getHours(), nowM = now.getMinutes();

  for (var i = 1; i < data.length; i++) {
    if (String(data[i][12]) !== chatId) continue;
    var rowDate = convertDateToString(data[i][5]);
    var rowTime = convertTimeToString(data[i][6]);
    var isPast = false;
    if (rowDate < todayStr) {
      isPast = true;
    } else if (rowDate === todayStr && rowTime) {
      var tp = rowTime.split(':');
      var rH = parseInt(tp[0])||0, rM = parseInt(tp[1])||0;
      if (rH < nowH || (rH === nowH && rM <= nowM)) isPast = true;
    }
    if (!isPast) continue;

    var masterId = data[i][3];
    if (masterId === undefined || masterId === null || masterId === '') masterId = getMasterIdByName(data[i][2]);

    result.push({
      id:            data[i][1],
      master:        data[i][2],
      masterId:      masterId,
      date:          rowDate,
      dateFormatted: formatDateTimeForDisplay(data[i][5], data[i][6]),
      time:          rowTime,
      services:      data[i][10],
      total:         data[i][11],
      status:        data[i][13]
    });
  }

  result.sort(function(a,b){ return a.date > b.date ? -1 : a.date < b.date ? 1 : 0; });

  var PAGE = 30;
  var offset = 0; // TODO: добавить пагинацию через params
  var page = result.slice(offset, offset + PAGE);
  return jsonOut({ bookings: page, hasMore: result.length > offset + PAGE, total: result.length });
}

/* ================================================================================
   АДМИН ФУНКЦИИ
   ================================================================================ */

function getAdminBookings(date, masterId, chatId) {
  if (!isAdmin(chatId)) return jsonOut({error: 'Unauthorized'});

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return jsonOut({bookings: []});

  var data = bookingsSheet.getDataRange().getValues();
  var result = [];

  for (var i = 1; i < data.length; i++) {
    var rowDate = convertDateToString(data[i][5]);
    var rowTime = convertTimeToString(data[i][6]);
    if (rowDate !== date) continue;

    var matchMaster = true;
    if (masterId) {
      var masterName = getMasterNameById(masterId);
      matchMaster = (data[i][3] !== undefined && parseInt(data[i][3]) === parseInt(masterId)) || data[i][2] === masterName;
    }

    if (matchMaster && data[i][13] !== 'cancelled') {
      result.push({
        date: rowDate, time: rowTime, name: data[i][7], phone: data[i][8],
        telegram: data[i][9], master: data[i][2], services: data[i][10],
        total: data[i][11], status: data[i][13]
      });
    }
  }

  result.sort(function(a,b){ return a.time < b.time ? -1 : 1; });
  return jsonOut({bookings: result});
}

function handleSlotAction(params) {
  if (!isAdmin(params.chatId)) return jsonOut({error: 'Unauthorized'});

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var blocksSheet = ss.getSheetByName('Blocks') || ss.insertSheet('Blocks');

  var masterName = params.master || getMasterNameById(params.masterId);
  var masterId   = params.masterId || getMasterIdByName(masterName);

  if (params.action === 'blockSlot') {
    blocksSheet.appendRow([masterName, masterId, "'" + params.date, "'" + params.slot, new Date(), '']);
  } else {
    var data = blocksSheet.getDataRange().getValues();
    for (var i = data.length - 1; i >= 1; i--) {
      if (data[i][0] === masterName && convertDateToString(data[i][2]) === params.date && convertTimeToString(data[i][3]) === params.slot) {
        blocksSheet.deleteRow(i + 1);
        break;
      }
    }
  }

  CacheService.getScriptCache().remove('allMastersSlots');
  return jsonOut({status: 'ok'});
}

function handleDayOff(params) {
  if (!isAdmin(params.chatId)) return jsonOut({error: 'Unauthorized'});

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var dayoffsSheet  = ss.getSheetByName('DayOffs') || ss.insertSheet('DayOffs');
  var bookingsSheet = ss.getSheetByName('Bookings');

  var masterName = params.master || getMasterNameById(params.masterId);
  var masterId   = params.masterId || getMasterIdByName(masterName);

  if (params.action === 'dayOff') {
    var hasBookings = false;
    var bookingsOnDate = [];
    if (bookingsSheet && bookingsSheet.getLastRow() > 1) {
      var bData = bookingsSheet.getDataRange().getValues();
      for (var i = 1; i < bData.length; i++) {
        var isMatch = (bData[i][2] === masterName) || (bData[i][3] !== undefined && parseInt(bData[i][3]) === parseInt(masterId));
        if (isMatch && convertDateToString(bData[i][5]) === params.date && bData[i][13] === 'confirmed') {
          hasBookings = true;
          bookingsOnDate.push({ time: convertTimeToString(bData[i][6]), name: bData[i][7], phone: bData[i][8] });
        }
      }
    }
    if (hasBookings) return jsonOut({ error: 'HasBookings', message: 'На эту дату есть записи', bookings: bookingsOnDate });

    dayoffsSheet.appendRow([masterName, masterId, "'" + params.date, new Date(), params.reason || '']);
    CacheService.getScriptCache().remove('allMastersSlots');
    return jsonOut({ success: true, status: 'ok' });
  }

  if (params.action === 'forceDayOff') {
    var cancelledClients = [];
    if (bookingsSheet && bookingsSheet.getLastRow() > 1) {
      var fData = bookingsSheet.getDataRange().getValues();
      for (var j = fData.length - 1; j >= 1; j--) {
        var isMatchF = (fData[j][2] === masterName) || (fData[j][3] !== undefined && parseInt(fData[j][3]) === parseInt(masterId));
        if (isMatchF && convertDateToString(fData[j][5]) === params.date && fData[j][13] === 'confirmed') {
          cancelledClients.push({ name: fData[j][7], phone: fData[j][8], time: convertTimeToString(fData[j][6]) });
          bookingsSheet.getRange(j + 1, 14).setValue('cancelled');
          // FIX-07: уведомляем клиентов об отмене из-за выходного
          var clientChatId = String(fData[j][12] || '');
          if (clientChatId) {
            sendTelegramMessageSafe(clientChatId,
              '❗️ <b>Запись отменена</b>\n\nВаша запись к мастеру <b>' + masterName + '</b> на ' + formatDateRu(params.date, 'full') + ' отменена — мастер в выходном.\n\nПожалуйста, запишитесь заново через приложение или позвоните нам: +7 (952) 560-88-98',
              {parse_mode: 'HTML'});
          }
        }
      }
    }
    dayoffsSheet.appendRow([masterName, masterId, "'" + params.date, new Date(), params.reason || '']);
    CacheService.getScriptCache().remove('allMastersSlots');
    return jsonOut({ success: true, status: 'ok', cancelledClients: cancelledClients });
  }

  if (params.action === 'removeDayOff') {
    var rData = dayoffsSheet.getDataRange().getValues();
    for (var k = rData.length - 1; k >= 1; k--) {
      var isMatchR = (rData[k][0] === masterName) || (rData[k][1] !== undefined && parseInt(rData[k][1]) === parseInt(masterId));
      if (isMatchR && convertDateToString(rData[k][2]) === params.date) {
        dayoffsSheet.deleteRow(k + 1);
        break;
      }
    }
    CacheService.getScriptCache().remove('allMastersSlots');
    return jsonOut({ success: true, status: 'ok' });
  }

  return jsonOut({status: 'ok'});
}

function getAllDayOffs(chatId) {
  if (!isAdmin(chatId)) return jsonOut({error: 'Unauthorized'});

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var dayoffsSheet = ss.getSheetByName('DayOffs');
  if (!dayoffsSheet) return jsonOut({dayoffs: []});

  var data = dayoffsSheet.getDataRange().getValues();
  var result = [];
  var todayStr = formatDateIso(new Date());

  for (var i = 1; i < data.length; i++) {
    var dateStr = convertDateToString(data[i][2]);
    if (dateStr < todayStr) continue;
    var masterName = data[i][0];
    var masterId = data[i][1];
    if (masterId === undefined || masterId === null || masterId === '') masterId = getMasterIdByName(masterName);
    result.push({ masterName: masterName, masterId: masterId, date: dateStr, dateFormatted: formatDateRu(data[i][2], 'full'), reason: data[i][4] || '' });
  }

  result.sort(function(a,b){ return a.date < b.date ? -1 : 1; });
  return jsonOut({dayoffs: result});
}

/* ================================================================================
   ОТЗЫВЫ
   ================================================================================ */

function getReviews(offset, limit) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var reviewsSheet = ss.getSheetByName('Reviews');
  if (!reviewsSheet) return jsonOut({reviews: [], hasMore: false});

  var data = reviewsSheet.getDataRange().getValues();
  var totalReviews = data.length - 1;
  var result = [];
  var count = 0;

  for (var i = data.length - 1 - offset; i >= 1 && count < limit; i--) {
    if (data[i][0]) {
      result.push({ name: data[i][0], text: data[i][1], rating: data[i][2], date: formatDateRu(data[i][3]), master: data[i][5] || '' });
      count++;
    }
  }
  return jsonOut({ reviews: result, hasMore: (offset + limit) < totalReviews, total: totalReviews });
}

function addReview(data) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var reviewsSheet = ss.getSheetByName('Reviews');
  if (!reviewsSheet) {
    reviewsSheet = ss.insertSheet('Reviews');
    reviewsSheet.appendRow(['Name','Text','Rating','Date','ChatId','Master']);
  }
  reviewsSheet.appendRow([data.name, data.text, data.rating, new Date(), data.chatId || '', data.master || '']);

  var stars = '';
  for (var s = 0; s < 5; s++) stars += s < data.rating ? '★' : '☆';
  sendTelegramMessageSafe(OWNER_CHAT_ID(), '⭐ <b>Новый отзыв!</b>\n\n👤 ' + data.name + '\n' + stars + '\n💬 ' + data.text, {parse_mode:'HTML'});

  return jsonOut({status: 'ok'});
}

/* ================================================================================
   АНАЛИТИКА
   ================================================================================ */

function getAnalytics(chatId) {
  if (!isAdmin(chatId)) return jsonOut({error: 'Unauthorized'});

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return jsonOut({ revenueToday:0, revenueWeek:0, revenueMonth:0, topServices:[], masterStats:[], totalBookings:0 });

  var data = bookingsSheet.getDataRange().getValues();
  var now = new Date(); now.setHours(0,0,0,0);
  var todayStart  = new Date(now);
  var weekStart   = new Date(now); weekStart.setDate(weekStart.getDate() - 7);
  var monthStart  = new Date(now.getFullYear(), now.getMonth(), 1);

  var revenueToday = 0, revenueWeek = 0, revenueMonth = 0;
  var serviceCount = {}, masterCount = {}, totalBookings = 0;

  for (var i = 1; i < data.length; i++) {
    if (data[i][13] !== 'confirmed') continue;
    var ds = convertDateToString(data[i][5]);
    if (!ds) continue;
    var dp = ds.split('-');
    var bd = new Date(parseInt(dp[0]), parseInt(dp[1])-1, parseInt(dp[2])); bd.setHours(0,0,0,0);
    var amount = parseAmount(data[i][11]);

    if (bd.getTime() === todayStart.getTime()) revenueToday += amount;
    if (bd >= weekStart) revenueWeek += amount;
    if (bd >= monthStart) {
      revenueMonth += amount;
      var svcs = (data[i][10] || '').split(', ');
      svcs.forEach(function(s){ if (s.trim()) serviceCount[s.trim()] = (serviceCount[s.trim()]||0) + 1; });
      if (data[i][2]) masterCount[data[i][2]] = (masterCount[data[i][2]]||0) + 1;
    }
    totalBookings++;
  }

  var masterStats = Object.keys(masterCount).map(function(n){ return {name:n, count:masterCount[n]}; });
  masterStats.sort(function(a,b){ return b.count - a.count; });
  var topServices = Object.keys(serviceCount).map(function(n){ return {name:n, count:serviceCount[n]}; });
  topServices.sort(function(a,b){ return b.count - a.count; });

  return jsonOut({ revenueToday, revenueWeek, revenueMonth, topServices: topServices.slice(0,10), masterStats, totalBookings });
}

/* ================================================================================
   КЛИЕНТЫ
   ================================================================================ */

function updateClientProfile(clientsSheet, data) {
  if (!clientsSheet) return;
  var chatId = String(data.clientChatId || '');
  if (!chatId) return;

  var cData = clientsSheet.getDataRange().getValues();
  var foundRow = -1;
  for (var i = 1; i < cData.length; i++) {
    if (String(cData[i][0]) === chatId) { foundRow = i + 1; break; }
  }

  var now = new Date();
  if (foundRow > 0) {
    clientsSheet.getRange(foundRow, 5).setValue(now);
    clientsSheet.getRange(foundRow, 7).setValue((parseInt(cData[foundRow-1][6])||0) + 1);
    clientsSheet.getRange(foundRow, 8).setValue((parseAmount(cData[foundRow-1][7])||0) + data.total);
  } else {
    clientsSheet.appendRow([chatId, data.name, data.phone, data.telegram||'', now, now, 1, data.total]);
  }
}

function getClients(search, chatId) {
  if (!isAdmin(chatId)) return jsonOut({error: 'Unauthorized'});
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var clientsSheet = ss.getSheetByName('Clients');
  if (!clientsSheet) return jsonOut({clients: []});

  var data = clientsSheet.getDataRange().getValues();
  var result = [];
  var sl = (search || '').toLowerCase();

  for (var i = 1; i < data.length; i++) {
    if (!data[i][0]) continue;
    var name = String(data[i][1]||''), phone = String(data[i][2]||''), tg = String(data[i][3]||'');
    if (!search || name.toLowerCase().indexOf(sl) !== -1 || phone.indexOf(search) !== -1 || tg.toLowerCase().indexOf(sl) !== -1) {
      result.push({ chatId: data[i][0], name, phone, telegram: tg, firstVisit: data[i][4], lastVisit: data[i][5], totalBookings: data[i][6], totalSpent: data[i][7] });
    }
  }
  return jsonOut({clients: result});
}

/* ================================================================================
   FIX-07: УВЕДОМЛЕНИЯ TELEGRAM
   ================================================================================ */

function sendBookingNotifications(data, bookingId, masterId) {
  var dateFormatted = formatDateTimeForDisplay(data.visitDateRaw, data.time);

  var ownerMsg =
    '✅ <b>Новая запись!</b>\n\n' +
    '👤 ' + data.name + '\n📞 ' + data.phone + '\n' +
    (data.telegram ? '📱 ' + data.telegram + '\n' : '') +
    '💇 ' + data.master + '\n📅 ' + dateFormatted + '\n' +
    '✂ ' + (data.services || 'Услуги не указаны') + '\n' +
    '💰 ' + data.total + ' ₽\n🆔 ' + bookingId;
  sendTelegramMessageSafe(OWNER_CHAT_ID(), ownerMsg, {parse_mode:'HTML'});

  // FIX-07: уведомление самому мастеру
  notifyMasterAboutNewBooking(masterId, data, dateFormatted, bookingId);

  if (data.clientChatId) {
    var clientMsg =
      '✅ <b>Вы записаны!</b>\n\n' +
      '💇 Мастер: ' + data.master + '\n📅 ' + dateFormatted + '\n' +
      '✂ Услуги: ' + (data.services || 'Услуги не указаны') + '\n' +
      '💰 Итого: ' + data.total + ' ₽\n\n' +
      '📍 г. Батайск, ул. Октябрьская, 108\n📞 +7 (952) 560-88-98';
    sendTelegramMessageSafe(data.clientChatId, clientMsg, {parse_mode:'HTML'});
  }
}

// FIX-07: найти chatId мастера в таблице Users и отправить уведомление
function notifyMasterAboutNewBooking(masterId, data, dateFormatted, bookingId) {
  if (masterId === null || masterId === undefined) return;
  var masterChatId = getMasterChatId(masterId);
  if (!masterChatId) return;
  var msg = '📋 <b>Новая запись к вам!</b>\n\n' +
    '👤 ' + data.name + '\n📞 ' + data.phone + '\n' +
    '📅 ' + dateFormatted + '\n✂ ' + (data.services || '') + '\n🆔 ' + bookingId;
  sendTelegramMessageSafe(masterChatId, msg, {parse_mode:'HTML'});
}

function notifyMasterAboutCancellation(masterId, clientName, date, time) {
  if (masterId === null || masterId === undefined) return;
  var masterChatId = getMasterChatId(masterId);
  if (!masterChatId) return;
  var msg = '❌ <b>Запись отменена</b>\n\n👤 ' + sanitizeHtml(String(clientName||'')) + '\n📅 ' + date + ' в ' + time;
  sendTelegramMessageSafe(masterChatId, msg, {parse_mode:'HTML'});
}

function getMasterChatId(masterId) {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var usersSheet = ss.getSheetByName('Users');
    if (!usersSheet || usersSheet.getLastRow() < 2) return null;
    var data = usersSheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][1]).toLowerCase() === 'master' && parseInt(data[i][2]) === parseInt(masterId)) {
        return String(data[i][0]);
      }
    }
  } catch (e) {}
  return null;
}

function sendTelegramMessageSafe(chatId, text, options) {
  try {
    var token = BOT_TOKEN();
    if (!token) { Logger.log('BOT_TOKEN не задан в ScriptProperties'); return false; }
    var url = 'https://api.telegram.org/bot' + token + '/sendMessage';
    var payload = { chat_id: chatId, text: text, parse_mode: (options && options.parse_mode) ? options.parse_mode : 'HTML' };
    var resp = UrlFetchApp.fetch(url, { method:'post', contentType:'application/json', payload:JSON.stringify(payload), muteHttpExceptions:true });
    return resp.getResponseCode() === 200;
  } catch (e) {
    Logger.log('Telegram error: ' + e.toString());
    return false;
  }
}

/* ================================================================================
   ПОДТВЕРЖДЕНИЕ ВИЗИТА ЗА 24 ЧАСА
   FIX-04: используем колонку 16 (ReminderStatus) вместо 15 (Notes)
   ================================================================================ */

function sendConfirmationRequests() {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return;

  var now = new Date();
  var data = bookingsSheet.getDataRange().getValues();

  for (var i = 1; i < data.length; i++) {
    if (data[i][13] !== 'confirmed') continue;
    // FIX-04: статус в колонке 16 (индекс 15)
    var reminderStatus = String(data[i][15] || '');
    if (reminderStatus === 'reminder_sent' || reminderStatus === 'confirmed_by_client') continue;

    var dateStr = convertDateToString(data[i][5]);
    var timeStr = convertTimeToString(data[i][6]);
    if (!dateStr || !timeStr) continue;

    var parts = dateStr.split('-'), tParts = timeStr.split(':');
    var bookingTime = new Date(parseInt(parts[0]), parseInt(parts[1])-1, parseInt(parts[2]), parseInt(tParts[0]), parseInt(tParts[1]));
    var hoursLeft = (bookingTime - now) / 3600000;
    if (hoursLeft < 23 || hoursLeft > 25) continue;

    var chatId = String(data[i][12] || '');
    if (!chatId) continue;

    var masterName = data[i][2];
    var bookingId  = data[i][1];
    var dateFormatted = formatDateTimeForDisplay(data[i][5], data[i][6]);

    var keyboard = { inline_keyboard: [[
      {text: '✅ Приду', callback_data: 'confirm_' + bookingId},
      {text: '❌ Отменить', callback_data: 'cancel_'  + bookingId}
    ]]};

    try {
      UrlFetchApp.fetch('https://api.telegram.org/bot' + BOT_TOKEN() + '/sendMessage', {
        method: 'post', contentType: 'application/json', muteHttpExceptions: true,
        payload: JSON.stringify({ chat_id: chatId, text: '<b>Напоминание о записи</b>\n\nМастер: ' + masterName + '\n' + dateFormatted + '\n\nПодтвердите, пожалуйста:', parse_mode: 'HTML', reply_markup: keyboard })
      });
      // FIX-04: пишем в колонку 16 (ReminderStatus)
      bookingsSheet.getRange(i + 1, 16).setValue('reminder_sent');
    } catch(e) {
      Logger.log('sendConfirmation error: ' + e.toString());
    }
  }
}

function doPost_confirmCallback(callbackQuery) {
  var cbData  = callbackQuery.data || '';
  var chatId  = String(callbackQuery.from.id);
  var msgId   = callbackQuery.message.message_id;

  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return;

  var data = bookingsSheet.getDataRange().getValues();

  if (cbData.indexOf('confirm_') === 0) {
    var bookingId = cbData.replace('confirm_', '');
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][1]) === bookingId) {
        // FIX-04: пишем в колонку 16
        bookingsSheet.getRange(i + 1, 16).setValue('confirmed_by_client');
        sendTelegramMessageSafe(chatId, 'Отлично! Ждём вас.\n\nАдрес: г. Батайск, ул. Октябрьская, 108', {});
        sendTelegramMessageSafe(OWNER_CHAT_ID(), '<b>Клиент подтвердил визит</b>\n\n' + sanitizeHtml(data[i][7]) + '\n' + data[i][2] + '\n' + formatDateTimeForDisplay(data[i][5], data[i][6]), {parse_mode:'HTML'});
        break;
      }
    }
  } else if (cbData.indexOf('cancel_') === 0) {
    var bookingId = cbData.replace('cancel_', '');
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][1]) === bookingId && data[i][13] === 'confirmed') {
        bookingsSheet.getRange(i + 1, 14).setValue('cancelled');
        CacheService.getScriptCache().remove('allMastersSlots');
        sendTelegramMessageSafe(chatId, 'Запись отменена.\n\nЕсли захотите перезаписаться — откройте приложение.', {});
        sendTelegramMessageSafe(OWNER_CHAT_ID(), '<b>Клиент отменил через подтверждение</b>\n\n' + sanitizeHtml(data[i][7]) + '\n' + data[i][2] + '\n' + formatDateTimeForDisplay(data[i][5], data[i][6]), {parse_mode:'HTML'});
        notifyMasterAboutCancellation(data[i][3], data[i][7], convertDateToString(data[i][5]), convertTimeToString(data[i][6]));
        break;
      }
    }
  }

  try {
    UrlFetchApp.fetch('https://api.telegram.org/bot' + BOT_TOKEN() + '/editMessageReplyMarkup', {
      method:'post', contentType:'application/json', muteHttpExceptions:true,
      payload: JSON.stringify({chat_id: chatId, message_id: msgId, reply_markup: {inline_keyboard:[]}})
    });
  } catch(e) {}
}

/* ================================================================================
   НАПОМИНАНИЯ
   ================================================================================ */

function sendReminders() {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var bookingsSheet = ss.getSheetByName('Bookings');
  if (!bookingsSheet) return;

  var now = new Date();
  var data = bookingsSheet.getDataRange().getValues();

  for (var i = 1; i < data.length; i++) {
    if (data[i][13] !== 'confirmed') continue;
    // FIX-04: проверяем Notes (колонка 15, индекс 14), а не ReminderStatus
    if (data[i][14]) continue;

    var dateStr = convertDateToString(data[i][5]);
    var timeStr = convertTimeToString(data[i][6]);
    if (!dateStr || !timeStr) continue;

    var parts = dateStr.split('-'), tParts = timeStr.split(':');
    var bookingTime = new Date(parseInt(parts[0]), parseInt(parts[1])-1, parseInt(parts[2]), parseInt(tParts[0]), parseInt(tParts[1]));
    var hoursDiff = (bookingTime - now) / 3600000;

    if (hoursDiff >= CONFIG.REMINDER_MIN_HOURS && hoursDiff <= CONFIG.REMINDER_MAX_HOURS) {
      var chatId = String(data[i][12] || '');
      if (!chatId) continue;
      var msg = '🔔 <b>Напоминание о записи!</b>\n\n💇 Мастер: ' + data[i][2] + '\n📅 ' + formatDateTimeForDisplay(data[i][5], data[i][6]) + '\n✂ Услуги: ' + (data[i][10]||'') + '\n\n📍 г. Батайск, ул. Октябрьская, 108';
      if (sendTelegramMessageSafe(chatId, msg, {parse_mode:'HTML'})) {
        // Пишем в Notes (колонка 15)
        bookingsSheet.getRange(i + 1, 15).setValue('reminder_sent');
      }
    }
  }
}

/* ================================================================================
   ТРИГГЕРЫ И ВЕБХУК
   ================================================================================ */

function setTelegramWebhook() {
  var scriptUrl = ScriptApp.getService().getUrl();
  var resp = UrlFetchApp.fetch('https://api.telegram.org/bot' + BOT_TOKEN() + '/setWebhook', {
    method:'post', contentType:'application/json', muteHttpExceptions:true,
    payload: JSON.stringify({url: scriptUrl})
  });
  Logger.log('Webhook: ' + resp.getContentText());
}


/* ================================================================================
   NEW-01: АВТОБЭКАП ТАБЛИЦЫ РАЗ В СУТКИ
   Триггер: ежедневно в 03:00
   Создаёт копию таблицы в той же папке Google Drive с датой в названии
   ================================================================================ */

function dailyBackup() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var dateStr = Utilities.formatDate(new Date(), 'Europe/Moscow', 'yyyy-MM-dd');
    var backupName = 'BarberStyle_Backup_' + dateStr;

    // Проверяем — не делали ли бэкап сегодня уже
    var files = DriveApp.getFilesByName(backupName);
    if (files.hasNext()) {
      Logger.log('Бэкап ' + backupName + ' уже существует, пропускаем');
      return;
    }

    // Копируем таблицу
    var originalFile = DriveApp.getFileById(SPREADSHEET_ID());
    var folder = originalFile.getParents().next();
    var copy = originalFile.makeCopy(backupName, folder);

    // Удаляем бэкапы старше 30 дней
    var cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 30);
    var allFiles = folder.getFiles();
    while (allFiles.hasNext()) {
      var f = allFiles.next();
      if (f.getName().indexOf('BarberStyle_Backup_') === 0 && f.getDateCreated() < cutoff) {
        f.setTrashed(true);
        Logger.log('Удалён старый бэкап: ' + f.getName());
      }
    }

    // Уведомляем владельца
    sendTelegramMessageSafe(OWNER_CHAT_ID(),
      '💾 <b>Бэкап создан</b>\n\n' +
      '📋 ' + backupName + '\n' +
      '📁 Сохранён в Google Drive рядом с основной таблицей\n' +
      '🗓 Хранятся последние 30 дней',
      {parse_mode: 'HTML'});

    Logger.log('✅ Бэкап создан: ' + backupName);
  } catch (e) {
    Logger.log('❌ Ошибка бэкапа: ' + e.toString());
    sendTelegramMessageSafe(OWNER_CHAT_ID(),
      '❌ <b>Ошибка бэкапа!</b>\n\n' + e.toString(),
      {parse_mode: 'HTML'});
  }
}

/* ================================================================================
   NEW-02: ЗАЩИТА ОТ СПАМА И ФЕЙКОВЫХ ЗАПИСЕЙ
   Многоуровневая защита:
   1. Honeypot-поле (скрытое поле которое боты заполняют)
   2. Анализ времени заполнения формы (слишком быстро = бот)
   3. Blocklist телефонов и chatId
   4. Проверка реального номера (формат)
   5. Ограничение частоты от одного IP/chatId (уже было, усилено)
   ================================================================================ */

// Лист Blocklist: ['Type','Value','Reason','CreatedAt']
// Type = 'phone' | 'chatId'

function isSpam(data) {
  var reasons = [];

  // Проверка 1: honeypot (поле website должно быть пустым — боты его заполняют)
  if (data.website && String(data.website).trim() !== '') {
    Logger.log('SPAM: honeypot заполнен');
    return { spam: true, reason: 'honeypot' };
  }

  // Проверка 2: слишком быстрая отправка (< 5 секунд с момента открытия)
  if (data.formOpenedAt) {
    var elapsed = Date.now() - parseInt(data.formOpenedAt);
    if (elapsed < 5000) {
      Logger.log('SPAM: форма заполнена за ' + elapsed + 'мс');
      return { spam: true, reason: 'too_fast' };
    }
  }

  // Проверка 3: blocklist
  var blocked = checkBlocklist(data.phone, data.clientChatId);
  if (blocked) {
    return { spam: true, reason: 'blocklist' };
  }

  // Проверка 4: подозрительное имя (только цифры, спецсимволы)
  if (data.name) {
    var nameClean = data.name.replace(/[^а-яёА-ЯЁa-zA-Z\s-]/g, '');
    if (nameClean.trim().length < 2) {
      return { spam: true, reason: 'invalid_name' };
    }
  }

  // Проверка 5: явно фейковый телефон (все одинаковые цифры)
  if (data.phone) {
    var digits = data.phone.replace(/\D/g, '');
    var uniqueDigits = digits.split('').filter(function(v, i, a) { return a.indexOf(v) === i; });
    if (uniqueDigits.length <= 2) {
      return { spam: true, reason: 'fake_phone' };
    }
  }

  return { spam: false };
}

function checkBlocklist(phone, chatId) {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var sheet = ss.getSheetByName('Blocklist');
    if (!sheet || sheet.getLastRow() < 2) return false;
    var data = sheet.getDataRange().getValues();
    var phoneDigits = phone ? phone.replace(/\D/g, '') : '';
    for (var i = 1; i < data.length; i++) {
      var type = String(data[i][0]);
      var value = String(data[i][1]);
      if (type === 'phone' && phoneDigits && value.replace(/\D/g,'') === phoneDigits) return true;
      if (type === 'chatId' && chatId && value === String(chatId)) return true;
    }
  } catch (e) {}
  return false;
}

function addToBlocklist(type, value, reason) {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var sheet = ss.getSheetByName('Blocklist');
    if (!sheet) {
      sheet = ss.insertSheet('Blocklist');
      sheet.appendRow(['Type', 'Value', 'Reason', 'CreatedAt']);
      var hr = sheet.getRange(1, 1, 1, 4);
      hr.setFontWeight('bold').setBackground('#c9a84c').setFontColor('#0a0805');
    }
    sheet.appendRow([type, value, reason || '', new Date()]);
    Logger.log('Добавлен в blocklist: ' + type + ' = ' + value);
  } catch (e) {
    Logger.log('addToBlocklist error: ' + e.toString());
  }
}

// Добавить в blocklist через GET: ?action=blockUser&type=phone&value=79001234567&chatId=ADMIN_ID
function handleBlockUser(params) {
  if (!isAdmin(params.chatId)) return jsonOut({error: 'Unauthorized'});
  addToBlocklist(params.type || 'phone', params.value, params.reason || '');
  return jsonOut({status: 'ok'});
}

/* ================================================================================
   NEW-03: СРЕДНИЙ ЧЕК И LTV КЛИЕНТА
   LTV = среднийЧек × среднееВизитовВМесяц × 12
   Добавляется в getAnalytics и в getClients
   ================================================================================ */

function getClientLTV(chatId) {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var clientsSheet = ss.getSheetByName('Clients');
    var bookingsSheet = ss.getSheetByName('Bookings');
    if (!clientsSheet || !bookingsSheet) return null;

    var cData = clientsSheet.getDataRange().getValues();
    var client = null;
    for (var i = 1; i < cData.length; i++) {
      if (String(cData[i][0]) === String(chatId)) { client = cData[i]; break; }
    }
    if (!client) return null;

    var totalSpent    = parseAmount(client[7]) || 0;
    var totalBookings = parseInt(client[6]) || 0;
    var firstVisit    = client[4] ? new Date(client[4]) : null;
    var lastVisit     = client[5] ? new Date(client[5]) : null;

    if (totalBookings === 0) return null;

    var avgCheck = totalBookings > 0 ? Math.round(totalSpent / totalBookings) : 0;

    // Месяцев активности клиента
    var monthsActive = 1;
    if (firstVisit && lastVisit) {
      monthsActive = Math.max(1, Math.round((lastVisit - firstVisit) / (1000 * 60 * 60 * 24 * 30)));
    }

    var visitsPerMonth = totalBookings / monthsActive;
    var ltv = Math.round(avgCheck * visitsPerMonth * 12);

    return {
      chatId:        chatId,
      name:          String(client[1] || ''),
      totalSpent:    totalSpent,
      totalBookings: totalBookings,
      avgCheck:      avgCheck,
      visitsPerMonth: Math.round(visitsPerMonth * 10) / 10,
      ltv:           ltv,
      firstVisit:    firstVisit ? formatDateIso(firstVisit) : '',
      lastVisit:     lastVisit  ? formatDateIso(lastVisit)  : ''
    };
  } catch (e) {
    Logger.log('getClientLTV error: ' + e.toString());
    return null;
  }
}

function getClientsWithLTV(search, chatId) {
  if (!isAdmin(chatId)) return jsonOut({error: 'Unauthorized'});
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
  var clientsSheet = ss.getSheetByName('Clients');
  if (!clientsSheet) return jsonOut({clients: []});

  var data = clientsSheet.getDataRange().getValues();
  var result = [];
  var sl = (search || '').toLowerCase();

  for (var i = 1; i < data.length; i++) {
    if (!data[i][0]) continue;
    var name  = String(data[i][1] || '');
    var phone = String(data[i][2] || '');
    var tg    = String(data[i][3] || '');
    if (search && name.toLowerCase().indexOf(sl) === -1 && phone.indexOf(search) === -1 && tg.toLowerCase().indexOf(sl) === -1) continue;

    var totalSpent    = parseAmount(data[i][7]) || 0;
    var totalBookings = parseInt(data[i][6])    || 0;
    var avgCheck      = totalBookings > 0 ? Math.round(totalSpent / totalBookings) : 0;

    var firstVisit = data[i][4] ? new Date(data[i][4]) : null;
    var lastVisit  = data[i][5] ? new Date(data[i][5]) : null;
    var monthsActive = 1;
    if (firstVisit && lastVisit) {
      monthsActive = Math.max(1, Math.round((lastVisit - firstVisit) / (1000 * 60 * 60 * 24 * 30)));
    }
    var visitsPerMonth = totalBookings / monthsActive;
    var ltv = Math.round(avgCheck * visitsPerMonth * 12);

    // Категория клиента
    var category = 'новый';
    if (totalBookings >= 10)    category = 'vip';
    else if (totalBookings >= 5) category = 'постоянный';
    else if (totalBookings >= 2) category = 'активный';

    result.push({
      chatId: data[i][0], name: name, phone: cleanPhoneValue(phone), telegram: tg,
      firstVisit:    firstVisit ? formatDateIso(firstVisit) : '',
      lastVisit:     lastVisit  ? formatDateIso(lastVisit)  : '',
      totalBookings: totalBookings,
      totalSpent:    totalSpent,
      avgCheck:      avgCheck,
      ltv:           ltv,
      category:      category
    });
  }

  // Сортируем по LTV убыванию
  result.sort(function(a, b) { return b.ltv - a.ltv; });
  return jsonOut({clients: result});
}

/* ================================================================================
   NEW-04: ПОТЕРЯННЫЕ КЛИЕНТЫ — уведомление через 20 дней отсутствия
   Триггер: ежедневно в 12:00
   Отправляет сообщение клиентам у которых lastVisit > 20 дней назад
   Не беспокоит тех у кого есть предстоящая запись
   ================================================================================ */

function sendWinbackMessages() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var clientsSheet  = ss.getSheetByName('Clients');
    var bookingsSheet = ss.getSheetByName('Bookings');
    if (!clientsSheet) return;

    var now = new Date();
    var cutoffDate = new Date(now.getTime() - 20 * 24 * 60 * 60 * 1000); // 20 дней назад
    var todayStr = formatDateIso(now);

    // Собираем chatId клиентов с предстоящими записями — их не трогаем
    var hasUpcoming = {};
    if (bookingsSheet && bookingsSheet.getLastRow() > 1) {
      var bData = bookingsSheet.getDataRange().getValues();
      for (var i = 1; i < bData.length; i++) {
        if (bData[i][13] !== 'confirmed') continue;
        var rowDate = convertDateToString(bData[i][5]);
        if (rowDate >= todayStr) {
          hasUpcoming[String(bData[i][12])] = true;
        }
      }
    }

    var cData = clientsSheet.getDataRange().getValues();
    var sent = 0;

    for (var j = 1; j < cData.length; j++) {
      var chatId = String(cData[j][0] || '');
      if (!chatId) continue;
      if (hasUpcoming[chatId]) continue; // уже записан — не трогаем

      var lastVisit = cData[j][5] ? new Date(cData[j][5]) : null;
      if (!lastVisit) continue;
      if (lastVisit > cutoffDate) continue; // был недавно — не трогаем

      // Проверяем — не отправляли ли уже winback за последние 20 дней
      var lastWinback = PropertiesService.getScriptProperties().getProperty('winback_' + chatId);
      if (lastWinback) {
        var lastWinbackDate = new Date(parseInt(lastWinback));
        if ((now - lastWinbackDate) < 20 * 24 * 60 * 60 * 1000) continue;
      }

      var name = String(cData[j][1] || 'друг');
      var firstName = name.split(' ')[0];

      var msg =
        '<b>Через час — клиент!</b>\n\n' +
        'Клиент: ' + clientName + '\n' +
        'Телефон: ' + clientPhone + '\n' +
        'Услуги: ' + services + '\n' +
        'Время: ' + timeStr + '\n\n' +
        'Не забудь подготовиться!';

      if (sendTelegramMessageSafe(masterChatId, msg, {parse_mode: 'HTML'})) {
        var newStatus = reminderStatus ? (reminderStatus + ',master_reminded') : 'master_reminded';
        bookingsSheet.getRange(i + 1, 16).setValue(newStatus);
        Logger.log('Мастеру ' + masterName + ' отправлено напоминание о записи в ' + timeStr);
      }
    }
  } catch(e) {
    Logger.log('sendMasterReminders error: ' + e.toString());
  }
}


/* ================================================================================
   NEW-06: СООБЩЕНИЕ ЧЕРЕЗ 2 ЧАСА ПОСЛЕ ВИЗИТА
   ================================================================================ */
function sendPostVisitThankYou() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var bookingsSheet = ss.getSheetByName('Bookings');
    if (!bookingsSheet) return;
    var now = new Date();
    var data = bookingsSheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (data[i][13] !== 'confirmed') continue;
      var reminderStatus = String(data[i][15] || '');
      if (reminderStatus.indexOf('thankyou_sent') !== -1) continue;
      var dateStr = convertDateToString(data[i][5]);
      var timeStr = convertTimeToString(data[i][6]);
      if (!dateStr || !timeStr) continue;
      var parts = dateStr.split('-'), tParts = timeStr.split(':');
      var visitTime = new Date(parseInt(parts[0]), parseInt(parts[1])-1, parseInt(parts[2]), parseInt(tParts[0]), parseInt(tParts[1]));
      var hoursAgo = (now - visitTime) / 3600000;
      if (hoursAgo < 2 || hoursAgo > 3) continue;
      var chatId = String(data[i][12] || '');
      if (!chatId) continue;
      var name = String(data[i][7] || '');
      var firstName = name.split(' ')[0] || 'друг';
      var masterName = String(data[i][2] || '');
      var msg = '<b>Спасибо за визит!</b>\n\n' +
        firstName + ', надеемся вам всё понравилось у мастера ' + masterName + '!\n\n' +
        'Оставьте отзыв прямо в приложении — это займёт 1 минуту!\n\n' +
        'До встречи в BARBER STYLE!';
      if (sendTelegramMessageSafe(chatId, msg, {parse_mode: 'HTML'})) {
        var newStatus = reminderStatus ? (reminderStatus + ',thankyou_sent') : 'thankyou_sent';
        bookingsSheet.getRange(i + 1, 16).setValue(newStatus);
      }
      Utilities.sleep(150);
    }
  } catch(e) {
    Logger.log('sendPostVisitThankYou error: ' + e.toString());
  }
}

/* ================================================================================
   NEW-07: ПОЗДРАВЛЕНИЕ С ДНЁМ РОЖДЕНИЯ + СКИДКА 20%
   ================================================================================ */
function sendBirthdayGreetings() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var clientsSheet = ss.getSheetByName('Clients');
    if (!clientsSheet) return;
    var now = new Date();
    var todayMonth = now.getMonth() + 1;
    var todayDay   = now.getDate();
    var data = clientsSheet.getDataRange().getValues();
    if (!data[0] || data[0].length < 9) return;
    var sent = 0;
    for (var i = 1; i < data.length; i++) {
      var chatId = String(data[i][0] || '');
      if (!chatId) continue;
      var birthday = data[i][8];
      if (!birthday) continue;
      var bMonth, bDay;
      var bStr = String(birthday);
      if (/^\d{2}\.\d{2}/.test(bStr)) {
        bDay   = parseInt(bStr.substring(0, 2));
        bMonth = parseInt(bStr.substring(3, 5));
      } else if (/^\d{4}-\d{2}-\d{2}/.test(bStr)) {
        var bParts = bStr.split('-');
        bMonth = parseInt(bParts[1]);
        bDay   = parseInt(bParts[2]);
      } else { continue; }
      if (bMonth !== todayMonth || bDay !== todayDay) continue;
      var bKey = 'birthday_' + chatId + '_' + now.getFullYear();
      if (PropertiesService.getScriptProperties().getProperty(bKey)) continue;
      var promoCode = 'BDAY' + chatId.slice(-4) + now.getFullYear().toString().slice(-2);
      var expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      PropertiesService.getScriptProperties().setProperty(
        'promo_' + promoCode,
        JSON.stringify({chatId: chatId, discount: 20, expires: expires.getTime()})
      );
      var name      = String(data[i][1] || '');
      var firstName = name.split(' ')[0] || '';
      var msg = '<b>С Днём рождения, ' + firstName + '!</b>\n\n' +
        'Команда BARBER STYLE поздравляет вас!\n\n' +
        'Специально для вас — скидка 20% на любую услугу!\n\n' +
        'Промокод: <code>' + promoCode + '</code>\n' +
        'Действует 7 дней\n\n' +
        'г. Батайск, ул. Октябрьская, 108';
      if (sendTelegramMessageSafe(chatId, msg, {parse_mode: 'HTML'})) {
        PropertiesService.getScriptProperties().setProperty(bKey, '1');
        sent++;
        sendTelegramMessageSafe(OWNER_CHAT_ID(),
          '<b>День рождения клиента</b>\n\n' + name + '\nПромокод: ' + promoCode + ' (-20%)',
          {parse_mode: 'HTML'});
      }
      Utilities.sleep(200);
    }
    if (sent > 0) Logger.log('Поздравлений отправлено: ' + sent);
  } catch(e) {
    Logger.log('sendBirthdayGreetings error: ' + e.toString());
  }
}

/* ================================================================================
   NEW-05: МАССОВАЯ РАССЫЛКА
   ================================================================================ */
function broadcastMessage(params) {
  if (!isAdmin(params.chatId)) return jsonOut({error: 'Unauthorized'});
  var message = params.message || '';
  if (!message || message.trim().length < 5) return jsonOut({error: 'Сообщение слишком короткое'});
  var lockKey = 'broadcast_lock';
  var lastBroadcast = PropertiesService.getScriptProperties().getProperty(lockKey);
  if (lastBroadcast && (Date.now() - parseInt(lastBroadcast)) < 60000) {
    return jsonOut({error: 'Подождите минуту между рассылками'});
  }
  PropertiesService.getScriptProperties().setProperty(lockKey, String(Date.now()));
  var filterCategory = params.filterCategory || 'all';
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var clientsSheet = ss.getSheetByName('Clients');
    if (!clientsSheet) return jsonOut({error: 'Clients sheet not found'});
    var data = clientsSheet.getDataRange().getValues();
    var sent = 0, skipped = 0;
    for (var i = 1; i < data.length; i++) {
      var chatId = String(data[i][0] || '');
      if (!chatId) { skipped++; continue; }
      if (filterCategory !== 'all') {
        var totalBookings = parseInt(data[i][6]) || 0;
        var category = 'новый';
        if (totalBookings >= 10)     category = 'vip';
        else if (totalBookings >= 5) category = 'постоянный';
        else if (totalBookings >= 2) category = 'активный';
        if (filterCategory === 'vip'     && category !== 'vip')        { skipped++; continue; }
        if (filterCategory === 'active'  && category !== 'активный')   { skipped++; continue; }
        if (filterCategory === 'regular' && category !== 'постоянный') { skipped++; continue; }
        if (filterCategory === 'new'     && category !== 'новый')      { skipped++; continue; }
      }
      var name = String(data[i][1] || '');
      var firstName = name.split(' ')[0] || '';
      var personalMsg = message.replace(/\{\{name\}\}/g, firstName);
      if (sendTelegramMessageSafe(chatId, personalMsg, {parse_mode: 'HTML'})) {
        sent++;
      } else { skipped++; }
      Utilities.sleep(100);
    }
    var report = '<b>Рассылка завершена</b>\n\nДоставлено: ' + sent + '\nПропущено: ' + skipped;
    sendTelegramMessageSafe(OWNER_CHAT_ID(), report, {parse_mode: 'HTML'});
    return jsonOut({status: 'ok', sent: sent, skipped: skipped});
  } catch(e) {
    return jsonOut({error: e.toString()});
  }
}

/* ================================================================================
   ВИТРИНА АКЦИЙ
   ================================================================================ */
function getPromos() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var settingsSheet = ss.getSheetByName('Settings');
    if (!settingsSheet) return jsonOut({promos: []});
    var data   = settingsSheet.getDataRange().getValues();
    var promos = [];
    for (var i = 1; i < data.length; i++) {
      var key = String(data[i][0] || '');
      if (key.indexOf('promo_') !== 0) continue;
      try {
        var val = String(data[i][1] || '');
        if (!val || val === '-') continue;
        promos.push(JSON.parse(val));
      } catch(e) {
        promos.push({name: String(data[i][1]), desc: String(data[i][2] || ''), type: 'sale'});
      }
    }
    return jsonOut({promos: promos});
  } catch(e) {
    return jsonOut({promos: []});
  }
}

/* ================================================================================
   П.13: УВЕДОМЛЕНИЕ МАСТЕРУ ЗА ЧАС ДО ЗАПИСИ
   ================================================================================ */
function sendMasterReminders() {
  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());
    var bookingsSheet = ss.getSheetByName('Bookings');
    var usersSheet    = ss.getSheetByName('Users');
    if (!bookingsSheet || !usersSheet) return;
    var now  = new Date();
    var data = bookingsSheet.getDataRange().getValues();
    var masterChatIds = {};
    var users = usersSheet.getDataRange().getValues();
    for (var u = 1; u < users.length; u++) {
      if (String(users[u][1]).toLowerCase() === 'master' && users[u][2] !== '') {
        masterChatIds[String(users[u][2])] = String(users[u][0]);
      }
    }
    for (var i = 1; i < data.length; i++) {
      if (data[i][13] !== 'confirmed') continue;
      var reminderStatus = String(data[i][15] || '');
      if (reminderStatus.indexOf('master_reminded') !== -1) continue;
      var dateStr = convertDateToString(data[i][5]);
      var timeStr = convertTimeToString(data[i][6]);
      if (!dateStr || !timeStr) continue;
      var parts  = dateStr.split('-'), tParts = timeStr.split(':');
      var visitTime = new Date(parseInt(parts[0]), parseInt(parts[1])-1, parseInt(parts[2]), parseInt(tParts[0]), parseInt(tParts[1]));
      var hoursLeft = (visitTime - now) / 3600000;
      if (hoursLeft < 1 || hoursLeft > 1.5) continue;
      var masterId    = String(data[i][3] || '');
      var masterName  = String(data[i][2] || '');
      var clientName  = String(data[i][7] || '');
      var clientPhone = String(data[i][8] || '');
      var services    = String(data[i][10] || '');
      var masterChatId = masterChatIds[masterId] || '';
      if (!masterChatId) continue;
      var msg = '<b>Через час — клиент!</b>\n\n' +
        'Клиент: ' + clientName + '\n' +
        'Телефон: ' + clientPhone + '\n' +
        'Услуги: ' + services + '\n' +
        'Время: ' + timeStr + '\n\n' +
        'Не забудь подготовиться!';
      if (sendTelegramMessageSafe(masterChatId, msg, {parse_mode: 'HTML'})) {
        var newStatus = reminderStatus ? (reminderStatus + ',master_reminded') : 'master_reminded';
        bookingsSheet.getRange(i + 1, 16).setValue(newStatus);
      }
    }
  } catch(e) {
    Logger.log('sendMasterReminders error: ' + e.toString());
  }
}

function setupTriggers() {
  // Удаляем все старые триггеры
  ScriptApp.getProjectTriggers().forEach(function(t){ ScriptApp.deleteTrigger(t); });

  // Каждый час — напоминания, подтверждения, "спасибо после визита"
  ScriptApp.newTrigger('sendReminders').timeBased().everyHours(1).create();
  ScriptApp.newTrigger('sendConfirmationRequests').timeBased().everyHours(1).create();
  ScriptApp.newTrigger('sendPostVisitThankYou').timeBased().everyHours(1).create();
  ScriptApp.newTrigger('sendMasterReminders').timeBased().everyHours(1).create();

  // Ежедневно в 03:00 — бэкап
  ScriptApp.newTrigger('dailyBackup')
    .timeBased().atHour(3).everyDays(1).create();

  // Ежедневно в 09:00 — поздравления с ДР
  ScriptApp.newTrigger('sendBirthdayGreetings')
    .timeBased().atHour(9).everyDays(1).create();

  // Ежедневно в 12:00 — winback (потерянные клиенты)
  ScriptApp.newTrigger('sendWinbackMessages')
    .timeBased().atHour(12).everyDays(1).create();

  Logger.log('✅ Все триггеры настроены (6 штук)');
}


/* ================================================================================
   AUTO SETUP — запусти один раз вручную в Apps Script
   Делает всё автоматически:
   ✅ Добавляет колонку Birthday в Clients
   ✅ Создаёт лист Blocklist
   ✅ Добавляет колонку ReminderStatus в Bookings если её нет
   ✅ Устанавливает все 6 триггеров
   ✅ Деплоит вебхук Telegram
   ✅ Отправляет отчёт владельцу
   ================================================================================ */

function autoSetup() {
  var report = [];
  var errors = [];

  try {
    var ss = SpreadsheetApp.openById(SPREADSHEET_ID());

    // ── 1. Clients: добавляем колонку Birthday (9-я) если нет ──
    var clientsSheet = ss.getSheetByName('Clients');
    if (clientsSheet) {
      var clientHeaders = clientsSheet.getRange(1, 1, 1, clientsSheet.getLastColumn()).getValues()[0];
      var hasBirthday = clientHeaders.indexOf('Birthday') !== -1;
      if (!hasBirthday) {
        var nextCol = clientsSheet.getLastColumn() + 1;
        clientsSheet.getRange(1, nextCol).setValue('Birthday');
        clientsSheet.getRange(1, nextCol)
          .setFontWeight('bold')
          .setBackground('#c9a84c')
          .setFontColor('#0a0805')
          .setHorizontalAlignment('center');
        clientsSheet.setColumnWidth(nextCol, 100);
        report.push('✅ Колонка Birthday добавлена в Clients (колонка ' + nextCol + ')');
      } else {
        report.push('ℹ️ Колонка Birthday уже есть в Clients');
      }
    } else {
      errors.push('❌ Лист Clients не найден');
    }

    // ── 2. Bookings: проверяем колонку ReminderStatus (16-я) ──
    var bookingsSheet = ss.getSheetByName('Bookings');
    if (bookingsSheet) {
      var bHeaders = bookingsSheet.getRange(1, 1, 1, Math.max(bookingsSheet.getLastColumn(), 16)).getValues()[0];
      if (!bHeaders[15] || bHeaders[15] === '') {
        bookingsSheet.getRange(1, 16).setValue('ReminderStatus');
        bookingsSheet.getRange(1, 16)
          .setFontWeight('bold')
          .setBackground('#c9a84c')
          .setFontColor('#0a0805')
          .setHorizontalAlignment('center');
        bookingsSheet.setColumnWidth(16, 120);
        report.push('✅ Колонка ReminderStatus добавлена в Bookings (колонка 16)');
      } else if (bHeaders[15] === 'ReminderStatus') {
        report.push('ℹ️ Колонка ReminderStatus уже есть в Bookings');
      } else {
        report.push('ℹ️ Колонка 16 в Bookings: ' + bHeaders[15]);
      }
    } else {
      errors.push('❌ Лист Bookings не найден');
    }

    // ── 3. Создаём лист Blocklist если нет ──
    var blocklistSheet = ss.getSheetByName('Blocklist');
    if (!blocklistSheet) {
      blocklistSheet = ss.insertSheet('Blocklist');
      blocklistSheet.appendRow(['Type', 'Value', 'Reason', 'CreatedAt']);
      var blHeader = blocklistSheet.getRange(1, 1, 1, 4);
      blHeader.setFontWeight('bold')
              .setBackground('#c9a84c')
              .setFontColor('#0a0805')
              .setHorizontalAlignment('center');
      blocklistSheet.setFrozenRows(1);
      blocklistSheet.setColumnWidth(1, 80);
      blocklistSheet.setColumnWidth(2, 150);
      blocklistSheet.setColumnWidth(3, 200);
      blocklistSheet.setColumnWidth(4, 120);
      report.push('✅ Лист Blocklist создан');
    } else {
      report.push('ℹ️ Лист Blocklist уже существует');
    }

    // ── 4. Создаём лист BroadcastLog если нет ──
    var broadcastSheet = ss.getSheetByName('BroadcastLog');
    if (!broadcastSheet) {
      broadcastSheet = ss.insertSheet('BroadcastLog');
      broadcastSheet.appendRow(['Date', 'Message', 'Sent', 'Skipped', 'Filter']);
      var blHeader2 = broadcastSheet.getRange(1, 1, 1, 5);
      blHeader2.setFontWeight('bold')
               .setBackground('#c9a84c')
               .setFontColor('#0a0805')
               .setHorizontalAlignment('center');
      broadcastSheet.setFrozenRows(1);
      report.push('✅ Лист BroadcastLog создан');
    } else {
      report.push('ℹ️ Лист BroadcastLog уже существует');
    }

    // ── 5а. Photo колонка в Masters если нет ──
    var mastersSheet = ss.getSheetByName('Masters');
    if (mastersSheet) {
      var mHeaders = mastersSheet.getRange(1, 1, 1, mastersSheet.getLastColumn()).getValues()[0];
      if (mHeaders.indexOf('Photo') === -1) {
        var photoCol = mastersSheet.getLastColumn() + 1;
        mastersSheet.getRange(1, photoCol).setValue('Photo');
        mastersSheet.getRange(1, photoCol).setFontWeight('bold').setBackground('#c9a84c').setFontColor('#0a0805').setHorizontalAlignment('center');
        mastersSheet.setColumnWidth(photoCol, 250);
        report.push('✅ Колонка Photo добавлена в Masters');
      } else {
        report.push('ℹ️ Колонка Photo уже есть в Masters');
      }
    }

    // ── 5б. Users: добавляем владельца как admin если таблица пуста ──
    var usersSheet = ss.getSheetByName('Users');
    if (usersSheet) {
      var uData = usersSheet.getDataRange().getValues();
      var ownerChatId = OWNER_CHAT_ID();
      var ownerExists = false;
      for (var u = 1; u < uData.length; u++) {
        if (String(uData[u][0]) === String(ownerChatId)) { ownerExists = true; break; }
      }
      if (!ownerExists && ownerChatId) {
        usersSheet.appendRow([ownerChatId, 'admin', '', 'Владелец', new Date()]);
        report.push('✅ Владелец добавлен в Users как admin (chatId: ' + ownerChatId + ')');
      } else {
        report.push('ℹ️ Владелец уже есть в Users');
      }
    }

    // ── 5в. Settings: добавляем базовые настройки если нет ──
    var settingsSheet = ss.getSheetByName('Settings');
    if (settingsSheet) {
      var sData = settingsSheet.getDataRange().getValues();
      var sKeys = sData.map(function(r) { return String(r[0]); });
      var defaultSettings = [
        ['workStart', '09:00', 'Начало рабочего дня'],
        ['workEnd', '21:00', 'Конец рабочего дня'],
        ['slotDuration', '60', 'Длительность слота (мин)'],
        ['currency', 'руб', 'Валюта'],
        ['address', 'г. Батайск, ул. Октябрьская, 108', 'Адрес'],
        ['phone', '+7 (952) 560-88-98', 'Телефон'],
        ['timezone', 'Europe/Moscow', 'Часовой пояс']
      ];
      var added = 0;
      defaultSettings.forEach(function(row) {
        if (sKeys.indexOf(row[0]) === -1) {
          settingsSheet.appendRow(row);
          added++;
        }
      });
      if (added > 0) report.push('✅ Добавлено ' + added + ' настроек в Settings');
      else report.push('ℹ️ Настройки Settings уже заполнены');
    }

    // ── 5г. Добавляем триггер sendMasterReminders если нет ──

    // ── 5. Удаляем старые триггеры, создаём новые ──
    var existingTriggers = ScriptApp.getProjectTriggers();
    existingTriggers.forEach(function(t) { ScriptApp.deleteTrigger(t); });
    report.push('✅ Старых триггеров удалено: ' + existingTriggers.length);

    ScriptApp.newTrigger('sendReminders').timeBased().everyHours(1).create();
    ScriptApp.newTrigger('sendConfirmationRequests').timeBased().everyHours(1).create();
    ScriptApp.newTrigger('sendPostVisitThankYou').timeBased().everyHours(1).create();
    ScriptApp.newTrigger('sendMasterReminders').timeBased().everyHours(1).create();
    ScriptApp.newTrigger('dailyBackup').timeBased().atHour(3).everyDays(1).create();
    ScriptApp.newTrigger('sendBirthdayGreetings').timeBased().atHour(9).everyDays(1).create();
    ScriptApp.newTrigger('sendWinbackMessages').timeBased().atHour(12).everyDays(1).create();
    report.push('✅ Создано 7 триггеров');

    // ── 6. Устанавливаем Telegram вебхук ──
    try {
      var scriptUrl = ScriptApp.getService().getUrl();
      var webhookResp = UrlFetchApp.fetch(
        'https://api.telegram.org/bot' + BOT_TOKEN() + '/setWebhook',
        { method:'post', contentType:'application/json', muteHttpExceptions:true,
          payload: JSON.stringify({url: scriptUrl}) }
      );
      var webhookResult = JSON.parse(webhookResp.getContentText());
      if (webhookResult.ok) {
        report.push('✅ Telegram вебхук установлен');
      } else {
        errors.push('⚠️ Вебхук: ' + webhookResult.description);
      }
    } catch (we) {
      errors.push('⚠️ Ошибка вебхука: ' + we.toString());
    }

    // ── 7. Проверяем ScriptProperties ──
    var props = PropertiesService.getScriptProperties().getProperties();
    var missingProps = [];
    if (!props.BOT_TOKEN)      missingProps.push('BOT_TOKEN');
    if (!props.OWNER_CHAT_ID)  missingProps.push('OWNER_CHAT_ID');
    if (!props.SPREADSHEET_ID) missingProps.push('SPREADSHEET_ID');

    if (missingProps.length === 0) {
      report.push('✅ Все ScriptProperties заполнены');
    } else {
      errors.push('❌ Не заполнены ScriptProperties: ' + missingProps.join(', '));
    }

    // ── Итоговый отчёт в лог ──
    Logger.log('\n=== AUTO SETUP ЗАВЕРШЁН ===');
    report.forEach(function(r) { Logger.log(r); });
    if (errors.length > 0) {
      Logger.log('\n=== ОШИБКИ ===');
      errors.forEach(function(e) { Logger.log(e); });
    }

    // ── Отправляем отчёт владельцу в Telegram ──
    var allLines = report.concat(errors.length > 0 ? ['\n⚠️ <b>Требуют внимания:</b>'].concat(errors) : []);
    var telegramReport =
      '🚀 <b>AutoSetup завершён!</b>\n\n' +
      '📸 Не забудь добавить фото мастеров в Sheets → Masters → Photo\n' +
      allLines.join('\n') +
      '\n\n<i>Версия: 5.0 — Barber Style</i>';

    if (props.BOT_TOKEN && props.OWNER_CHAT_ID) {
      sendTelegramMessageSafe(OWNER_CHAT_ID(), telegramReport, {parse_mode: 'HTML'});
    }

    // ── Показываем итог в UI ──
    var ui = SpreadsheetApp.getUi();
    var summary = errors.length === 0
      ? '✅ Всё настроено успешно!\n\n' + report.join('\n')
      : '⚠️ Настроено с предупреждениями:\n\n' + report.join('\n') + '\n\nТребуют внимания:\n' + errors.join('\n');
    ui.alert('BARBER STYLE — Auto Setup', summary, ui.ButtonSet.OK);

  } catch (e) {
    Logger.log('autoSetup FATAL: ' + e.toString());
    try {
      SpreadsheetApp.getUi().alert('Ошибка autoSetup', e.toString(), SpreadsheetApp.getUi().ButtonSet.OK);
    } catch(ue) {}
  }
}

/* ================================================================================
   ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ОТВЕТА
   ================================================================================ */

function jsonOut(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
