let mainArea = document.getElementById("main-area")

/* Login */

let loginArea = document.getElementById("login-area")
let loginForm = document.getElementById("login-form")
let passwordField = document.getElementById("password")
let passwordInvalid = document.getElementById("password-status")
let loginButton = document.getElementById("login")

loginButton.addEventListener('click', login)
loginForm.addEventListener('submit', login)

function login(e) {
    e.preventDefault()

    let password = passwordField.value
    let salt = CryptoJS.enc.Base64.parse(config.salt)
    let key = CryptoJS.PBKDF2(password, salt, {
        keySize: config.keySize * 8 / 32,
        iterations: config.iterations,
        hasher: CryptoJS.algo.SHA256
    });

    let method = 'GET'
    let path = '/verify'
    let url = 'https://' + location.host + path

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')
    xhr.setRequestHeader('Authorization', generateAuthHmacForNow(key, method, path))

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && xhr.status === 200) {
            storeKey(key)
            showMainArea()
        } else if (xhr.readyState === 4 && xhr.status === 401) {
            passwordInvalid.classList.remove('invisible')
        }
    })

    xhr.send()
}

/* Logout */

let logoutButton = document.getElementById("logout-button")

logoutButton.addEventListener('click', logout)
if (config.salt) {
    logoutButton.classList.remove('hidden')
}

function logout() {
    clearKey()
    showLoginArea()
}

/* Drag & drop */

let dropArea = document.getElementById('drop-area');

function showDropZone() {
    dropArea.style.visibility = "visible";
}
function hideDropZone() {
    dropArea.style.visibility = "hidden";
}

function allowDrag(e) {
    if (true) {  // Test that the item being dragged is a valid one
        e.dataTransfer.dropEffect = 'copy';
        e.preventDefault();
    }
}

function handleDrop(e) {
    e.preventDefault();
    hideDropZone();
    handleFile(e.dataTransfer.files[0])
}

function installDropListeners() {
    window.addEventListener('dragenter', showDropZone);
    dropArea.addEventListener('dragenter', allowDrag);
    dropArea.addEventListener('dragover', allowDrag);
    dropArea.addEventListener('dragleave', hideDropZone);
    dropArea.addEventListener('drop', handleDrop);
}

function removeDropListeners() {
    window.removeEventListener('dragenter', showDropZone);
    dropArea.removeEventListener('dragenter', allowDrag);
    dropArea.removeEventListener('dragover', allowDrag);
    dropArea.removeEventListener('dragleave', hideDropZone);
    dropArea.removeEventListener('drop', handleDrop);
}

/* Text field & saving text */

let text = document.getElementById("text")
let saveButton = document.getElementById("save-button")
let saveStatus = document.getElementById('save-status')

saveButton.addEventListener('click', save)

text.value = ''
text.addEventListener('keydown', keyHandler,false)

function keyHandler(e) {
    if (e.keyCode === 9) { // <tab>
        var start = text.selectionStart;
        var end = text.selectionEnd;

        text.value = text.value.substring(0, start) + "\t" + text.value.substring(end)
        text.selectionStart = text.selectionEnd = start + 1;

        e.preventDefault()
    }
}

function save() {
    let method = 'PUT'
    let path = '/' + (fileId.value || 'default')
    let url = 'https://' + location.host + path
    let key = loadKey()

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    if (key) {
        xhr.setRequestHeader('Authorization', generateAuthHmacForNow(key, method, path))
    }

    xhr.upload.addEventListener("progress", function (e) {
        saveStatus.innerHTML = 'Saving'
    })

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState == 4 && xhr.status == 200) {
            saveStatus.innerHTML = 'Saved'
        } else if (xhr.readyState == 4 && xhr.status != 200) {
            saveStatus.innerHTML = 'Error ' + xhr.status
        }
    })

    xhr.send(text.value)
}

/* Uploading */

let fileId = document.getElementById("file-id")
let uploadButton = document.getElementById("upload-button")
let uploadStatus = document.getElementById('upload-status')
let fileUpload = document.getElementById("file-upload")

fileId.value = ''
uploadButton.addEventListener('click', function() { fileUpload.click() })

function handleFile(file) {
    uploadStatus.innerHTML = '0%'
    uploadFile(file)
}

function uploadFile(file) {
    let method = 'PUT'
    let path = '/' + (fileId.value || 'default')
    let url = 'https://' + location.host + path
    let key = loadKey()

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    if (key) {
        xhr.setRequestHeader('Authorization', generateAuthHmacForNow(key, method, path))
    }

    xhr.overrideMimeType(file.type);
    xhr.upload.addEventListener("progress", function (e) {
        uploadStatus.innerHTML = Math.round((e.loaded * 100.0 / e.total) || 100) + '%'
    })

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState == 4 && xhr.status == 200) {
            uploadStatus.innerHTML = 'Uploaded'
        } else if (xhr.readyState == 4 && xhr.status != 200) {
            uploadStatus.innerHTML = 'Error ' + xhr.status
        }
    })

    xhr.send(file)
}

/* Show/hide password area */

let loggedIn = !config.salt || loadKey()
if (loggedIn) {
    showMainArea()
} else {
    showLoginArea()
}

function showMainArea() {
    loginArea.classList.add('hidden')
    mainArea.classList.remove('hidden')
    text.focus()
    installDropListeners()
}

function showLoginArea() {
    mainArea.classList.add('hidden')
    loginArea.classList.remove('hidden')
    logoutButton.classList.remove('hidden')
    passwordInvalid.classList.add('invisible')
    passwordField.focus()
    removeDropListeners()
}

/* Util functions */

// See util.go/GenerateAuthHmac
function generateAuthHmac(key, method, path, timestamp, ttl) {
    let message = `${timestamp}:${ttl}:${method}:${path}`
    let hash = CryptoJS.HmacSHA256(message, key)
    let hashBase64 = hash.toString(CryptoJS.enc.Base64)
    return `HMAC ${timestamp} ${ttl} ${hashBase64}`
}

function generateAuthHmacForNow(key, method, path) {
    return generateAuthHmac(key, method, path, Math.floor(new Date().getTime()/1000), 0)
}

function storeKey(key) {
    localStorage.setItem('key', key.toString())
}

function loadKey() {
    if (localStorage.getItem('key')) {
        return CryptoJS.enc.Hex.parse(localStorage.getItem('key'))
    } else {
        return null
    }
}

function clearKey() {
    localStorage.removeItem('key')
}
