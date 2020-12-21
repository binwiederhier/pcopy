let mainArea = document.getElementById("main-area")
let textArea = document.getElementById("text-area")
let dropArea = document.getElementById("drop-area")

let idField = document.getElementById("id")
let progressBar = document.getElementById('progress-bar')

let passwordArea = document.getElementById("password-area")
let passwordField = document.getElementById("password")
let passwordInvalid = document.getElementById("password-status")
let loginButton = document.getElementById("login")

let key = false;

loginButton.addEventListener('click', login)

;['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, preventDefaults, false)
    document.body.addEventListener(eventName, preventDefaults, false)
})

;['dragenter', 'dragover'].forEach(eventName => {
    dropArea.addEventListener(eventName, highlight, false)
})

;['dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, unhighlight, false)
})

if (config.salt) {
    passwordArea.classList.remove('hidden');
} else {
    mainArea.classList.remove('hidden');
}

// Handle dropped files
dropArea.addEventListener('drop', handleDrop, false)

function preventDefaults(e) {
    e.preventDefault()
    e.stopPropagation()
}

function highlight(e) {
    dropArea.classList.add('highlight')
}

function unhighlight(e) {
    dropArea.classList.remove('highlight')
}

function handleDrop(e) {
    handleFile(e.dataTransfer.files[0])
}

function handleFile(file) {
    progressBar.value = 0
    uploadFile(file)
}

function uploadFile(file) {
    let method = 'PUT'
    let path = '/c/' + (idField.value || 'default')
    let url = 'https://' + location.host + path

    let xhr = new XMLHttpRequest()
    xhr.open(method, url)
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    if (key) {
        xhr.setRequestHeader('Authorization', generateAuthHmacForNow(key, method, path))
    }

    xhr.overrideMimeType(file.type);
    xhr.upload.addEventListener("progress", function (e) {
        progressBar.value = (e.loaded * 100.0 / e.total) || 100
    })

    xhr.addEventListener('readystatechange', function (e) {
        if (xhr.readyState == 4 && xhr.status == 200) {
            progressBar.value = 100
        } else if (xhr.readyState == 4 && xhr.status != 200) {
            // Error. Inform the user
        }
    })

    xhr.send(file)
}

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

function login() {
    let password = passwordField.value
    let salt = CryptoJS.enc.Base64.parse(config.salt)

    key = CryptoJS.PBKDF2(password, salt, {
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
            passwordArea.classList.add('hidden')
            mainArea.classList.remove('hidden')
        } else if (xhr.readyState === 4 && xhr.status === 401) {
            passwordInvalid.classList.remove('hidden')
        }
    })

    xhr.send()
}