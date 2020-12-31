/* All the things */

let mainArea = document.getElementById("main-area")
let dropArea = document.getElementById('drop-area');

let text = document.getElementById("text")
let headerSaveButton = document.getElementById("save-button")
let headerLogoutButton = document.getElementById("logout-button")
let headerFileId = document.getElementById("file-id")
let headerUploadButton = document.getElementById("upload-button")
let headerFileUpload = document.getElementById("file-upload")

let loginButton = document.getElementById("login")
let loginArea = document.getElementById("login-area")
let loginForm = document.getElementById("login-form")
let loginPasswordField = document.getElementById("password")
let loginPasswordInvalid = document.getElementById("password-status")

let infoArea = document.getElementById("info-area")
let infoBoxUploading = document.getElementById("info-box-uploading")
let infoUploadProgressTitle = document.getElementById("info-uploading-title")
let infoUploadProgressStatus = document.getElementById("info-uploading-status")
let infoBoxFinished = document.getElementById("info-box-finished")
let infoDirectLink = document.getElementById("info-direct-link")
let infoCommandPpaste = document.getElementById("info-command-ppaste")
let infoCommandCurl = document.getElementById("info-command-curl")

/* Login */

loginButton.addEventListener('click', login)
loginForm.addEventListener('submit', login)

function login(e) {
    e.preventDefault()

    let password = loginPasswordField.value
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
            loginPasswordInvalid.classList.remove('invisible')
        }
    })

    xhr.send()
}

/* Logout */

headerLogoutButton.addEventListener('click', logout)
if (config.salt) {
    headerLogoutButton.classList.remove('hidden')
}

function logout() {
    clearKey()
    showLoginArea()
}

/* Drag & drop */

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

headerSaveButton.addEventListener('click', save)

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
    showUploadProgress('Saving', '')

    let method = 'PUT'
    let path = '/' + (headerFileId.value || 'default')
    let url = 'https://' + location.host + path
    let key = loadKey()

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    if (key) {
        xhr.setRequestHeader('Authorization', generateAuthHmacForNow(key, method, path))
    }

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && xhr.status === 200) {
            showInfoUploadFinished(url, path, key)
        } else if (xhr.readyState === 4 && xhr.status !== 200) {
            updateUploadProgress('Error ' + xhr.status)
        }
    })

    xhr.send(text.value)
}

/* Uploading */

headerFileId.value = ''
headerUploadButton.addEventListener('click', function() { headerFileUpload.click() })

function handleFile(file) {
    uploadFile(file)
}

function showUploadProgress(title, status) {
    infoUploadProgressTitle.innerHTML = title
    infoUploadProgressStatus.innerHTML = status
    infoBoxUploading.classList.remove("hidden")
    infoBoxFinished.classList.add("hidden")
    infoArea.classList.remove("hidden")
}

function showInfoUploadFinished(url, path, key) {
    infoCommandPpaste.innerHTML = headerFileId.value ? 'ppaste ' + headerFileId.value : 'ppaste'
    if (key) {
        let authParam = generateAuthHmacParamForNow(key, 'GET', path)
        let directLink = `${url}?a=${authParam}`
        infoDirectLink.href = directLink
        infoCommandCurl.innerHTML = `curl -k "${directLink}"`
    } else {
        infoDirectLink.href = url
        infoCommandCurl.innerHTML = `curl "${url}`
    }
    infoBoxUploading.classList.add("hidden")
    infoBoxFinished.classList.remove("hidden")
}

function updateUploadProgress(status) {
    infoUploadProgressStatus.innerHTML = status
}

function uploadFile(file) {
    showUploadProgress('Uploading', '0%')

    let method = 'PUT'
    let path = '/' + (headerFileId.value || 'default')
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
        updateUploadProgress(Math.round((e.loaded * 100.0 / e.total) || 100) + '%')
    })

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && xhr.status === 200) {
            showInfoUploadFinished(url, path, key)
        } else if (xhr.readyState === 4 && xhr.status !== 200) {
            updateUploadProgress('Error ' + xhr.status)
        }
    })

    xhr.send(file)
}

/* Info area */

let hasClickClass = (el) => {
    for (var c of el.classList.values()) {
        if (["container", "section", "t", "tc"].indexOf(c) !== -1) {
            return true
        }
    }
    return false
}

infoArea.addEventListener('click', function(e) {
    if (!hasClickClass(e.target)) return;

    infoArea.classList.add("fade-out")
    infoArea.addEventListener('transitionend', function handler() {
        infoArea.classList.add("hidden")
        infoArea.classList.remove("fade-out")
        infoArea.removeEventListener('transitionend', handler)
    })
})

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
    headerLogoutButton.classList.remove('hidden')
    loginPasswordInvalid.classList.add('invisible')
    loginPasswordField.focus()
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

function generateAuthHmacParamForNow(key, method, path) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(generateAuthHmacForNow(key, method, path)))
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
