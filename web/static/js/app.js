
/**
 * Hello, dear curious visitor. I am not a web-guy, so please don't judge my horrible JS code.
 * In fact, please do tell me about all the things I did wrong and that I could improve. I've been trying
 * to read up on modern JS, but it's just a little much.
 *
 * Feel free to open tickets at https://github.com/binwiederhier/pcopy/issues. Thank you!
 */

/* All the things */

let mainArea = document.getElementById("main-area")
let dropArea = document.getElementById('drop-area');

let text = document.getElementById("text")
let headerSaveButton = document.getElementById("save-button")
let headerLogoutButton = document.getElementById("logout-button")
let headerFileId = document.getElementById("file-id")
let headerRandomFileId = document.getElementById("random-file-id")
let headerStream = document.getElementById("stream")
let headerUploadButton = document.getElementById("upload-button")
let headerFileUpload = document.getElementById("file-upload")

let loginButton = document.getElementById("login")
let loginArea = document.getElementById("login-area")
let loginForm = document.getElementById("login-form")
let loginPasswordField = document.getElementById("password")
let loginPasswordInvalid = document.getElementById("password-status")

let infoArea = document.getElementById("info-area")

let infoUploadHeaderActive = document.getElementById("info-header-upload-active")
let infoUploadHeaderFinished = document.getElementById("info-header-upload-finished")
let infoUploadTitleActive = document.getElementById("info-title-upload-active")

let infoStreamHeaderActive = document.getElementById("info-header-stream-active")
let infoStreamHeaderFinished = document.getElementById("info-header-stream-finished")
let infoStreamTitleActive = document.getElementById("info-title-stream-active")

let infoErrorHeader = document.getElementById("info-error-header")
let infoErrorCode = document.getElementById("info-error-code")
let infoErrorTextBadRequest = document.getElementById("info-error-text-400")


let infoLinks = document.getElementById("info-links")
let infoDirectLinkStream = document.getElementById("info-direct-link-stream")
let infoDirectLinkDownload = document.getElementById("info-direct-link-download")
let infoCommandPpaste = document.getElementById("info-command-ppaste")
let infoCommandPpasteCopy = document.getElementById("info-command-ppaste-copy")
let infoCommandCurl = document.getElementById("info-command-curl")
let infoCommandCurlCopy = document.getElementById("info-command-curl-copy")

/* Login */

loginButton.addEventListener('click', login)
loginForm.addEventListener('submit', login)

function login(e) {
    e.preventDefault()

    let password = loginPasswordField.value
    let salt = CryptoJS.enc.Base64.parse(config.KeySalt)
    let key = CryptoJS.PBKDF2(password, salt, {
        keySize: config.KeyLenBytes * 8 / 32,
        iterations: config.KeyDerivIter,
        hasher: CryptoJS.algo.SHA256
    });

    let method = 'GET'
    let path = '/verify'
    let url = 'https://' + location.host + path

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')
    xhr.setRequestHeader('Authorization', generateAuthHMAC(key, method, path))

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
if (config.KeySalt) {
    headerLogoutButton.classList.remove('hidden')
}

function logout() {
    clearKey()
    showLoginArea()
}

/* Drag & drop */

function showDropZone() {
    dropArea.style.visibility = "visible";
    hideInfoArea()
}

function hideDropZone() {
    dropArea.style.visibility = "hidden";
}

function allowDrag(e) {
    e.dataTransfer.dropEffect = 'copy';
    e.preventDefault();
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

/* File ID */

let previousFileId = ''
headerFileId.value = ''
headerRandomFileId.checked = randomFileIdEnabled()
changeRandomFileIdEnabled(randomFileIdEnabled())

headerRandomFileId.addEventListener('change', (e) => { changeRandomFileIdEnabled(e.target.checked) })

function changeRandomFileIdEnabled(enabled) {
    storeRandomFileIdEnabled(enabled)
    if (enabled) {
        previousFileId = headerFileId.value
        headerFileId.value = ''
        headerFileId.disabled = true
        headerFileId.placeholder = '(randomly chosen)'
    } else {
        headerFileId.value = previousFileId
        headerFileId.disabled = false
        headerFileId.placeholder = 'default (optional)'
    }
}

/* Stream */

headerStream.checked = streamEnabled()
headerStream.addEventListener('change', (e) => { storeStreamEnabled(e.target.checked) })

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
    } else if (e.ctrlKey && e.keyCode === 13) { // <ctrl>+<return>
        e.preventDefault()
        text.blur()
        save()
    }
}

function save() {
    let streaming = streamEnabled()
    let fileId = getFileId()
    let method = 'PUT'
    let path = '/' + fileId
    let url = 'https://' + location.host + path
    let key = loadKey()

    progressStart(fileId, url, path, key)

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    if (key) {
        xhr.setRequestHeader('Authorization', generateAuthHMAC(key, method, path))
    }

    if (streaming) {
        xhr.setRequestHeader('Content-Type', 'inode/fifo')
    }

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && xhr.status === 200) {
            progressFinish()
        } else if (xhr.readyState === 4 && xhr.status !== 200) {
            progressFailed(xhr.status)
        }
    })

    xhr.send(text.value)
}

/* Uploading */

headerUploadButton.addEventListener('click', function() { headerFileUpload.click() })

function handleFile(file) {
    uploadFile(file)
}

function progressStart(fileId, url, path, key) {
    url = maybeAddAuthParam(url, path, key)

    infoCommandPpaste.value = fileId === "default" ? 'ppaste' : 'ppaste ' + fileId
    infoDirectLinkStream.href = url
    infoDirectLinkDownload.href = url
    infoCommandCurl.value = generateCurlCommand(url)

    progressHideHeaders()

    if (streamEnabled()) {
        infoStreamTitleActive.innerHTML = 'Streaming ...'
        infoLinks.classList.remove('hidden')
        infoStreamHeaderActive.classList.remove('hidden')
    } else {
        infoUploadTitleActive.innerHTML = 'Uploading ...'
        infoLinks.classList.add('hidden')
        infoUploadHeaderActive.classList.remove('hidden')
    }

    infoArea.classList.remove('error')
    infoArea.classList.remove("hidden")
}

function progressUpdate(progress) {
    if (streamEnabled()) {
        infoStreamTitleActive.innerHTML = `Streaming ... ${progress}%`
    } else {
        infoUploadTitleActive.innerHTML = `Uploading ... ${progress}%`
    }
}

function progressFinish() {
    progressHideHeaders()

    if (streamEnabled()) {
        infoLinks.classList.add('hidden')
        infoStreamHeaderFinished.classList.remove('hidden')
    } else {
        infoLinks.classList.remove('hidden')
        infoUploadHeaderFinished.classList.remove('hidden')
    }
}

function progressFailed(code) {
    progressHideHeaders()

    infoArea.classList.add('error')
    infoLinks.classList.add('hidden')
    infoErrorCode.innerHTML = code
    if (code === 400) {
        infoErrorTextBadRequest.classList.remove('hidden')
    } else {
        infoErrorTextBadRequest.classList.add('hidden')
    }
    infoErrorHeader.classList.remove('hidden')
}

function progressHideHeaders() {
    Array
        .from(document.getElementsByClassName("info-header"))
        .forEach((el) => el.classList.add('hidden'))
}

function uploadFile(file) {
    let streaming = streamEnabled()
    let fileId = getFileId()
    let method = 'PUT'
    let path = '/' + fileId
    let url = 'https://' + location.host + path
    let key = loadKey()

    progressStart(fileId, url, path, key)

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    if (key) {
        xhr.setRequestHeader('Authorization', generateAuthHMAC(key, method, path))
    }

    if (streaming) {
        xhr.setRequestHeader('Content-Type', 'inode/fifo')
    }

    xhr.overrideMimeType(file.type);
    xhr.upload.addEventListener("progress", function (e) {
        let progress = Math.round((e.loaded * 100.0 / e.total) || 100)
        progressUpdate(progress)
    })

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && xhr.status === 200) {
            progressFinish()
        } else if (xhr.readyState === 4 && xhr.status !== 200) {
            progressFailed(xhr.status)
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

infoArea.addEventListener('click', fadeOutInfoArea)

function hideInfoArea() {
    infoArea.classList.add("hidden")
    infoArea.classList.remove("fade-out")
}

function fadeOutInfoArea(e) {
    if (!hasClickClass(e.target)) return;

    infoArea.classList.add("fade-out")
    infoArea.addEventListener('transitionend', function handler() {
        hideInfoArea()
        infoArea.removeEventListener('transitionend', handler)
    })
}

infoCommandPpasteCopy.addEventListener('click', function() {
    infoCommandPpaste.select();
    infoCommandPpaste.setSelectionRange(0, 99999); /* For mobile devices */
    document.execCommand("copy");
    infoCommandPpaste.setSelectionRange(0, 0);
    infoCommandPpaste.blur()
})

infoCommandCurlCopy.addEventListener('click', function() {
    infoCommandCurl.select();
    infoCommandCurl.setSelectionRange(0, 99999); /* For mobile devices */
    document.execCommand("copy");
    infoCommandCurl.setSelectionRange(0, 0);
    infoCommandCurl.blur()
})

/* Show/hide password area */

let loggedIn = !config.KeySalt || loadKey()
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

function generateAuthHMAC(key, method, path) {
    return generateAuthHMACWithTTL(key, method, path, config.FileExpireAfter)
}

function generateAuthHMACParam(key, method, path) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(generateAuthHMAC(key, method, path)))
}

// See crypto.go/GenerateAuthHMAC
function generateAuthHMACWithTTL(key, method, path, ttl) {
    let timestamp = Math.floor(new Date().getTime()/1000)
    let message = `${timestamp}:${ttl}:${method}:${path}`
    let hash = CryptoJS.HmacSHA256(message, key)
    let hashBase64 = hash.toString(CryptoJS.enc.Base64)
    return `HMAC ${timestamp} ${ttl} ${hashBase64}`
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

function getFileId() {
    if (randomFileIdEnabled()) {
        return Math.random().toString(36).slice(2)
    } else {
        return (headerFileId.value || 'default')
    }
}

function storeRandomFileIdEnabled(randomFileId) {
    localStorage.setItem('randomName', randomFileId)
}

function randomFileIdEnabled() {
    if (localStorage.getItem('randomName') !== null) {
        return localStorage.getItem('randomName') === 'true'
    } else {
        return false
    }
}

function storeStreamEnabled(streamEnabled) {
    localStorage.setItem('streamEnabled', streamEnabled)
}

function streamEnabled() {
    if (localStorage.getItem('streamEnabled') !== null) {
        return localStorage.getItem('streamEnabled') === 'true'
    } else {
        return false
    }
}

function generateCurlCommand(url) {
    if (config.CurlPinnedPubKey !== "") {
        return `curl -k --pinnedpubkey ${config.CurlPinnedPubKey} "${url}"`
    } else {
        return `curl "${url}"`
    }
}

function maybeAddAuthParam(url, path, key) {
    if (key) {
        let authParam = generateAuthHMACParam(key, 'GET', path)
        return `${url}?a=${authParam}`
    } else {
        return url
    }
}