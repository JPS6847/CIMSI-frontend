'use strict' ;

const urlInput = document.getElementById('urlImagen');
const imgPreview = document.getElementById('previewImagen');

urlInput.addEventListener('input', () => {
    const url = urlInput.value.trim();
    if (url) {
        imgPreview.src = url;
    } else {
        imgPreview.src = '';
    }
});