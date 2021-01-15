
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
let headerInfoButton = document.getElementById("info-button")
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
let infoCloseButton = document.getElementById("info-close-button")

let infoHelpHeader = document.getElementById("info-help-header")
let infoHelpJoinCommand = document.getElementById("info-command-join")
let infoHelpJoinCommandCopy = document.getElementById("info-command-join-copy")
let infoHelpJoinCommandTooltip = document.getElementById("info-command-join-tooltip")

let infoUploadHeaderActive = document.getElementById("info-upload-header-active")
let infoUploadHeaderFinished = document.getElementById("info-upload-header-finished")
let infoUploadTitleActive = document.getElementById("info-upload-title-active")

let infoStreamHeaderActive = document.getElementById("info-stream-header-active")
let infoStreamHeaderFinished = document.getElementById("info-stream-header-finished")
let infoStreamHeaderInterrupted = document.getElementById("info-stream-header-interrupted")
let infoStreamTitleActive = document.getElementById("info-stream-title-active")

let infoErrorHeader = document.getElementById("info-error-header")
let infoErrorCode = document.getElementById("info-error-code")
let infoErrorTextLimitReached = document.getElementById("info-error-text-limit-reached")

let infoLinks = document.getElementById("info-links")
let infoDirectLinkStream = document.getElementById("info-direct-link-stream")
let infoDirectLinkDownload = document.getElementById("info-direct-link-download")
let infoTabLinkPcopy = document.getElementById("info-tab-link-pcopy")
let infoTabLinkCurl = document.getElementById("info-tab-link-curl")
let infoCommandDirectLink = document.getElementById("info-command-link")
let infoCommandDirectLinkCopy = document.getElementById("info-command-link-copy")
let infoCommandDirectLinkTooltip = document.getElementById("info-command-link-tooltip")
let infoCommandLine = document.getElementById("info-command-line")
let infoCommandLineCopy = document.getElementById("info-command-line-copy")
let infoCommandLineTooltip = document.getElementById("info-command-line-tooltip")

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
    if (allowSubmit) {
        dropArea.style.visibility = "visible";
        hideInfoArea()
    }
}

function hideDropZone() {
    dropArea.style.visibility = "hidden";
}

function allowDrag(e) {
    if (allowSubmit) {
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

/* File ID */

let previousFileId = ''
headerFileId.value = ''

/* File ID: input validation */

let allowSubmit = true
headerFileId.addEventListener('keyup', fileIdChanged)
headerFileId.addEventListener('paste', fileIdChanged)

function fileIdChanged(e) {
    let textValid = headerFileId.value === "" || /^[0-9a-z][-_.0-9a-z]*$/i.test(headerFileId.value)
    if (textValid) {
        allowSubmit = true
        headerFileId.classList.remove('error')
        headerSaveButton.disabled = false
        headerUploadButton.disabled = false
    } else {
        allowSubmit = false
        headerFileId.classList.add('error')
        headerSaveButton.disabled = true
        headerUploadButton.disabled = true
    }
}

/* File ID: random name checkbox */

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

/* Stream checkbox */

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
    if (!allowSubmit) {
        return
    }

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
        xhr.setRequestHeader('X-Stream', 'yes')
    }

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && (xhr.status === 200 || xhr.status === 206)) {
            progressFinish(xhr.status)
        } else if (xhr.readyState === 4 && xhr.status !== 200) {
            progressFailed(xhr.status)
        }
    })

    xhr.send(text.value)
}

/* Info help */

headerInfoButton.addEventListener('click', function() {
    let serverAddr = location.host.replace(':' + config.DefaultPort, '')
    infoHelpJoinCommand.value = `pcopy join ${serverAddr}`

    progressHideHeaders()
    infoLinks.classList.add('hidden')
    infoArea.classList.remove('error')
    infoArea.classList.remove("hidden")
    infoHelpHeader.classList.remove('hidden')
})

infoHelpJoinCommandCopy.addEventListener('click', function() {
    infoHelpJoinCommand.select();
    infoHelpJoinCommand.setSelectionRange(0, 99999); /* For mobile devices */
    document.execCommand("copy");
    infoHelpJoinCommand.setSelectionRange(0, 0);
    infoHelpJoinCommand.blur()
    infoHelpJoinCommandTooltip.innerHTML = 'Copied'
    infoHelpJoinCommandTooltip.classList.add('copied')
})

/* Uploading */

headerUploadButton.addEventListener('click', function() { headerFileUpload.click() })

function handleFile(file) {
    uploadFile(file)
}

function progressStart(fileId, url, path, key) {
    url = maybeAddAuthParam(url, path, key)

    infoDirectLinkStream.href = url
    infoDirectLinkDownload.href = url
    infoCommandDirectLink.value = url

    infoTabLinkPcopy.classList.add('tab-active')
    infoTabLinkCurl.classList.remove('tab-active')
    infoCommandLine.dataset.pcopy = fileId === "default" ? 'ppaste' : 'ppaste ' + fileId
    infoCommandLine.dataset.curl = generateCurlCommand(url)
    infoCommandLine.value = infoCommandLine.dataset.pcopy

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

function progressFinish(code) {
    progressHideHeaders()

    if (streamEnabled()) {
        infoLinks.classList.add('hidden')
        if (code === 206) {
            infoStreamHeaderInterrupted.classList.remove('hidden')
        } else {
            infoStreamHeaderFinished.classList.remove('hidden')
        }
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
    if (code === 429 || code === 413) { // 429 Too Many Request, or 413 Payload Too Large
        infoErrorTextLimitReached.classList.remove('hidden')
    } else {
        infoErrorTextLimitReached.classList.add('hidden')
    }
    infoErrorHeader.classList.remove('hidden')
}

function progressHideHeaders() {
    Array
        .from(document.getElementsByClassName("info-header"))
        .forEach((el) => el.classList.add('hidden'))
}

function uploadFile(file) {
    if (!allowSubmit) {
        return
    }

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
        xhr.setRequestHeader('X-Stream', 'yes')
    }

    xhr.overrideMimeType(file.type);
    xhr.upload.addEventListener("progress", function (e) {
        let progress = Math.round((e.loaded * 100.0 / e.total) || 100)
        progressUpdate(progress)
    })

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState === 4 && (xhr.status === 200 || xhr.status === 206)) {
            progressFinish(xhr.status)
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

infoCloseButton.addEventListener('click', function (e) {
    e.preventDefault()
    fadeOutInfoArea()
})

infoArea.addEventListener('click', function (e) {
    if (!hasClickClass(e.target)) return;
    fadeOutInfoArea(e)
})

function hideInfoArea() {
    infoArea.classList.add("hidden")
    infoArea.classList.remove("fade-out")
}

function fadeOutInfoArea(e) {
    infoArea.classList.add("fade-out")
    infoArea.addEventListener('transitionend', function handler() {
        hideInfoArea()
        infoArea.removeEventListener('transitionend', handler)
    })
}

infoTabLinkPcopy.addEventListener('click', function(e) {
    e.preventDefault()
    infoTabLinkPcopy.classList.add('tab-active')
    infoTabLinkCurl.classList.remove('tab-active')
    infoCommandLine.value = infoCommandLine.dataset.pcopy
})

infoTabLinkCurl.addEventListener('click', function(e) {
    e.preventDefault()
    infoTabLinkPcopy.classList.remove('tab-active')
    infoTabLinkCurl.classList.add('tab-active')
    infoCommandLine.value = infoCommandLine.dataset.curl
})

infoCommandDirectLinkCopy.addEventListener('click', function() {
    infoCommandDirectLink.select();
    infoCommandDirectLink.setSelectionRange(0, 99999); /* For mobile devices */
    document.execCommand("copy");
    infoCommandDirectLink.setSelectionRange(0, 0);
    infoCommandDirectLink.blur()
    infoCommandDirectLinkTooltip.innerHTML = 'Copied'
    infoCommandDirectLinkTooltip.classList.add('copied')
})

infoCommandDirectLinkCopy.addEventListener('mouseout', function() {
    infoCommandDirectLinkTooltip.innerHTML = 'Copy to clipboard'
    infoCommandDirectLinkTooltip.classList.remove('copied')
})

infoCommandLineCopy.addEventListener('click', function() {
    infoCommandLine.select();
    infoCommandLine.setSelectionRange(0, 99999); /* For mobile devices */
    document.execCommand("copy");
    infoCommandLine.setSelectionRange(0, 0);
    infoCommandLine.blur()
    infoCommandLineTooltip.innerHTML = 'Copied'
    infoCommandLineTooltip.classList.add('copied')

})

infoCommandLineCopy.addEventListener('mouseout', function() {
    infoCommandLineTooltip.innerHTML = 'Copy to clipboard'
    infoCommandLineTooltip.classList.remove('copied')
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
        return `curl --pinnedpubkey ${config.CurlPinnedPubKey} -sSLk "${url}"`
    } else {
        return `curl -sSL "${url}"`
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