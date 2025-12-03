'use strict';

document.addEventListener("DOMContentLoaded", function() {
    const form = document.querySelector("form");
    const container = document.querySelector(".container");

    form.addEventListener("submit", function(event) {
        const passwd = document.getElementById("contrasenya");
        const passwd2 = document.getElementById("contrasenya2");

        const oldAlert = document.querySelector(".alert");
        if (oldAlert) oldAlert.remove();

        let alertMessage = "";

        if (passwd.value !== passwd2.value) {
            event.preventDefault();
            alertMessage = "Las contraseñas no coinciden.";
        } else if (!passwd.checkValidity()) {
            event.preventDefault();
            alertMessage = "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.";
        }

        if (alertMessage !== "") {
            const alertDiv = document.createElement("div");
            alertDiv.className = "alert alert-danger alert-dismissible fade show mt-3";
            alertDiv.role = "alert";
            alertDiv.innerHTML = `
                ${alertMessage}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;

            const title = container.querySelector("h2");
            if (title) {
                title.insertAdjacentElement("afterend", alertDiv);
            } else {
                form.prepend(alertDiv);
            }
        }
    });
});
