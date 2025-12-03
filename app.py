from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, send_file, make_response
import pymysql
import os
from werkzeug.security import *
from werkzeug.utils import secure_filename
from pdf2image import *  
from PIL import *
import stripe
import mysql.connector
import io
import zipfile


app = Flask(__name__)
app.secret_key = os.urandom(24)
stripe.api_key = "sk_test_51STP1iGwh0Yq6j7KUBItJ6clELwtRuM0gf826pMgxmh9txthkRjjK2ADsIz7A1niF4FY51JTkgBRrufAfJsOrxmY00tHWOuQFt"
STRIPE_PUBLIC_KEY = "pk_test_51STP1iGwh0Yq6j7Kbe0KxPN9tcJiFxyKveX56yPIDhKDkDNXxH3qcAJPhH4YdsQDArPeRJJL2j42LGC4ENsWZvie00QbCQvQSX"


def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='flask_app',
        port=3307,
        password='flask',
        database='tienda_partituras',
        cursorclass=pymysql.cursors.DictCursor
    )


@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT p.id, p.nombre, p.precio, p.fecha, i.url, u.nombreUsuario, i.thumbnail_url, u.fotoPerfil FROM partituras p
                   LEFT JOIN imagenes i ON p.id = i.partitura_id
                   LEFT JOIN usuarios u ON p.usuario_id = u.id 
                   WHERE fecha >= CURDATE() - INTERVAL 2 DAY 
                   ORDER BY fecha DESC""")
    partituras = cursor.fetchall()
    conn.close()
    return render_template('index.html', partituras=partituras)


@app.route('/partitura/<int:partitura_id>')
def detalle_partitura(partitura_id):
    estrellas = request.args.get('estrellas')  # parámetro GET opcional

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # 1) Partitura
    cursor.execute("""
        SELECT p.id, p.nombre, p.precio, p.fecha, p.descripcion,
               u.nombreUsuario, i.thumbnail_url, i.url
        FROM partituras p
        LEFT JOIN imagenes i ON p.id = i.partitura_id
        LEFT JOIN usuarios u ON p.usuario_id = u.id
        WHERE p.id = %s
    """, (partitura_id,))
    partitura = cursor.fetchone()

    if not partitura:
        conn.close()
        return "Partitura no encontrada", 404

    # 2) Comentarios + valoraciones (lista de dicts) — aseguramos que c.id existe
    sql_valoraciones = """
        SELECT 
            c.id AS id,
            c.texto AS texto,
            v.numEstrellas AS numEstrellas,
            v.fecha AS fecha,
            u.nombreUsuario AS nombreUsuario
        FROM valoraciones v
        JOIN comentarios c ON v.id = c.valoracion_id
        LEFT JOIN usuarios u ON v.usuario_id = u.id
        WHERE v.partitura_id = %s
    """
    params = [partitura_id]

    if estrellas and estrellas.isdigit() and int(estrellas) in range(1, 6):
        sql_valoraciones += " AND v.numEstrellas = %s"
        params.append(int(estrellas))

    sql_valoraciones += " ORDER BY v.id DESC"

    cursor.execute(sql_valoraciones, params)
    comentarios_valoraciones = cursor.fetchall()  # lista de dicts

    # 2b) Traer respuestas de los comentarios (defensivo: comprobar existencia de ids)
    comentario_ids = [c['id'] for c in comentarios_valoraciones if c and c.get('id') is not None]

    respuestas = {}
    if comentario_ids:
        format_strings = ','.join(['%s'] * len(comentario_ids))
        cursor.execute(f"""
            SELECT r.id AS id, r.comentario_id AS comentario_id, r.texto AS texto, r.fecha AS fecha, u.nombreUsuario AS nombreUsuario
            FROM respuestas r
            JOIN usuarios u ON r.usuario_id = u.id
            WHERE r.comentario_id IN ({format_strings})
            ORDER BY r.fecha ASC
        """, comentario_ids)

        for r in cursor.fetchall():
            # defensa extra: salta filas sin comentario_id válido
            cid = r.get('comentario_id')
            if cid is None:
                continue
            respuestas.setdefault(cid, []).append(r)

    # 3) Estadísticas (globales, no filtradas)
    cursor.execute("""
        SELECT
            COUNT(*) AS total,
            ROUND(AVG(numEstrellas), 2) AS media,
            SUM(CASE WHEN numEstrellas = 5 THEN 1 ELSE 0 END) AS cinco,
            SUM(CASE WHEN numEstrellas = 4 THEN 1 ELSE 0 END) AS cuatro,
            SUM(CASE WHEN numEstrellas = 3 THEN 1 ELSE 0 END) AS tres,
            SUM(CASE WHEN numEstrellas = 2 THEN 1 ELSE 0 END) AS dos,
            SUM(CASE WHEN numEstrellas = 1 THEN 1 ELSE 0 END) AS uno
        FROM valoraciones
        WHERE partitura_id = %s
    """, (partitura_id,))
    row_stats = cursor.fetchone()

    if row_stats and row_stats.get('total', 0) > 0:
        total = int(row_stats['total'])
        media = float(row_stats['media'] or 0)
        counts = {k: int(row_stats[k] or 0) for k in ['cinco','cuatro','tres','dos','uno']}
        porcentajes = {k: round(v / total * 100, 1) for k, v in counts.items()}
        stats = {
            'total': total,
            'media': round(media, 2),
            'media_redondeada': int(round(media)),
            **counts,
            'porcentajes': porcentajes
        }
    else:
        stats = None

    # 4) ¿Ha comprado el usuario esta partitura?
    usuario_id = session.get("usuario_id")
    usuario_ha_comprado = False

    if usuario_id:
        cursor.execute("""
            SELECT lc.id
            FROM lineasCompra lc
            JOIN compras c ON c.id = lc.compra_id
            WHERE lc.partitura_id = %s
              AND c.usuario_id = %s
              AND c.estadoPago = 'completado'
            LIMIT 1
        """, (partitura_id, usuario_id))
        if cursor.fetchone():
            usuario_ha_comprado = True

    conn.close()

    return render_template(
        'imagen.html',
        partitura=partitura,
        comentarios_valoraciones=comentarios_valoraciones,
        usuario_ha_comprado=usuario_ha_comprado,
        stats=stats,
        respuestas=respuestas
    )

@app.route('/partitura/<int:partitura_id>/valorar', methods=['POST'])
def valorar(partitura_id):
    if 'usuario_id' not in session:
        flash('Debes iniciar sesión para poder dejar una reseña.', 'warning')
        
    num_estrellas = int(request.form['numEstrellas'])
    comentario_texto = request.form.get('comentario', '').strip()
    usuario_id = session.get('usuario_id') 

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO valoraciones (numEstrellas, partitura_id, usuario_id) VALUES (%s, %s, %s)",
        (num_estrellas, partitura_id, usuario_id)
    )
    valoracion_id = cursor.lastrowid

    if comentario_texto:
        cursor.execute(
            "INSERT INTO comentarios (texto, valoracion_id) VALUES (%s, %s)",
            (comentario_texto, valoracion_id)
        )

    conn.commit()
    conn.close()

    return redirect(url_for('detalle_partitura', partitura_id=partitura_id))


@app.route('/comentario/<int:comentario_id>/responder', methods=['POST'])
def responder_comentario(comentario_id):
    if 'usuario_id' not in session:
        flash('Debes iniciar sesión para poder responder.', 'warning')
        return redirect(request.referrer or url_for('index'))

    texto_respuesta = request.form.get('texto_respuesta', '').strip()
    if not texto_respuesta:
        flash('El texto de la respuesta no puede estar vacío.', 'warning')
        return redirect(request.referrer or url_for('index'))

    usuario_id = session.get('usuario_id')

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute(
        "INSERT INTO respuestas (texto, comentario_id, usuario_id) VALUES (%s, %s, %s)",
        (texto_respuesta, comentario_id, usuario_id)
    )
    conn.commit()

    # Recuperar partitura vinculada al comentario
    cursor.execute("""
        SELECT v.partitura_id
        FROM comentarios c
        JOIN valoraciones v ON c.valoracion_id = v.id
        WHERE c.id = %s
    """, (comentario_id,))

    row = cursor.fetchone()
    if not row:
        conn.close()
        flash('Comentario no encontrado.', 'warning')
        return redirect(url_for('index'))

    partitura_id = row['partitura_id']

    conn.close()
    return redirect(url_for('detalle_partitura', partitura_id=partitura_id))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nombre = request.form['nombreUsuario']
        email = request.form['email']
        contrasena = request.form['contrasenya']
        hashed_password = generate_password_hash(contrasena)

        # Foto usuario
        foto_file = request.files.get('fotoPerfil')
        if foto_file and foto_file.filename != '':
            filename = secure_filename(foto_file.filename)
            foto_path = os.path.join('static', 'images', 'perfiles', filename)
            foto_file.save(foto_path)
            foto_perfil = f'images/perfiles/{filename}'
        else:
            foto_perfil = 'images/perfiles/default_profile.png'

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insertar nuevo usuario
        cursor.execute(
            "INSERT INTO usuarios (nombreUsuario, email, contrasenya, fotoPerfil) VALUES (%s, %s, %s, %s)",
            (nombre, email, hashed_password, foto_perfil)
        )
        conn.commit()
        usuario_id = cursor.lastrowid
        conn.close()

        # Guardar los datos en la sesión
        session['usuario_id'] = usuario_id
        session['usuario_nombre'] = nombre
        session['usuario_foto'] = foto_perfil

        flash('Usuario registrado correctamente', 'success')
        return redirect(url_for('login'))  
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nombre = request.form['nombreUsuario']
        contrasena = request.form['contrasenya']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE nombreUsuario=%s", (nombre,))
        usuario = cursor.fetchone()
        conn.close()

        if usuario and check_password_hash(usuario['contrasenya'], contrasena):
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario['nombreUsuario']
            session['usuario_foto'] = usuario.get('fotoPerfil')
            cargar_carrito_en_sesion(usuario['id'])
            flash('Has iniciado sesión correctamente', 'success')
            return redirect(url_for('index'))
        else:
            flash('Correo o contraseña incorrectos', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'usuario_id' in session:
        guardar_carrito_desde_sesion(session['usuario_id'])
    session.clear()  # Elimina todos los datos de la sesión
    flash('Has cerrado sesión correctamente', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        nombre = request.form['nombrePartitura']
        precio = request.form['precio']
        descripcion = request.form['descripcion']
        usuario_id = session.get('usuario_id')

        # Guardar PDF
        pdf_file = request.files['urlPDF']
        filename = secure_filename(pdf_file.filename)
        pdf_path = os.path.join('upload_pdfs', filename)
        pdf_file.save(pdf_path)

        # Crear thumbnail PDF
        pages = convert_from_path(pdf_path, 
                                  poppler_path=r"C:\Users\dalva\OneDrive\Escritorio\Release-25.07.0-0\poppler-25.07.0\Library\bin")
        thumbnail = pages[0]
        thumbnail_filename = filename.rsplit('.', 1)[0] + '.png'
        thumbnail_path = os.path.join('static', 'thumbnails', thumbnail_filename)
        thumbnail.save(thumbnail_path, 'PNG')

        # Guardar thumbnail en BD
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO partituras(nombre, precio, fecha, descripcion, usuario_id) VALUES (%s, %s, CURDATE(), %s, %s)",
                       (nombre, precio, descripcion, usuario_id))
        
        partitura_id = cursor.lastrowid

        cursor.execute("INSERT INTO imagenes(url, thumbnail_url, partitura_id) VALUES (%s, %s, %s)", 
                       (filename, f"thumbnails/{thumbnail_filename}", partitura_id))
        conn.commit()
        conn.close()

        flash('Partitura subida correctamente', 'success')
        return redirect(url_for('index'))
    return render_template('upload.html')

@app.route('/partituras', methods=['GET', 'POST'])
def catalogo():
    conn = get_db_connection()
    cursor = conn.cursor()

    orden = request.args.get('orden', 'fecha_desc')
    precio_min = request.args.get('precio_min', None)
    precio_max = request.args.get('precio_max', None)
    busqueda = request.args.get('q', None)

    query = "SELECT p.id, p.nombre, p.precio, p.fecha, i.url, i.thumbnail_url, u.nombreUsuario, u.fotoPerfil FROM partituras p " \
    "LEFT JOIN imagenes i ON p.id = i.partitura_id " \
    "LEFT JOIN usuarios u ON p.usuario_id = u.id " \
    "WHERE 1=1"
    params = []

    # Filtrar por nombre
    if busqueda:
        query += " AND p.nombre LIKE %s"
        params.append(f"%{busqueda}%")

    # Filtrar por rango de precio
    if precio_min:
        query += " AND p.precio >= %s"
        params.append(float(precio_min))
    if precio_max:
        query += " AND p.precio <= %s"
        params.append(float(precio_max))
    
    # Ordenar
    if orden == 'fecha_asc':
        query += " ORDER BY p.fecha ASC"
    elif orden == 'fecha_desc':
        query += " ORDER BY p.fecha DESC"
    elif orden == 'precio_asc':
        query += " ORDER BY p.precio ASC"
    elif orden == 'precio_desc':
        query += " ORDER BY p.precio DESC"

    cursor.execute(query, params)
    partituras = cursor.fetchall()
    conn.close()
    
    return render_template('catalogo.html', partituras=partituras, orden=orden, precio_min=precio_min, precio_max=precio_max, 
                           busqueda=busqueda)

@app.route('/descargar/<int:partitura_id>')
def descargar(partitura_id):
    # 1. Verificar si el usuario ha comprado y pagado la partitura
    # 2. Si ha pagado -> enviar pdf
    # 3. Si no ha pagado -> mensaje

    # Verificar si el usuario está loggeado
    usuario_id = session.get('usuario_id')
    if not usuario_id:
        flash("Debes iniciar sesión con una cuenta de usuario para poder proseguir con la compra.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute("SELECT lc.id FROM lineasCompra lc " \
    " JOIN compras c ON c.id = lc.compra_id" \
    " WHERE lc.partitura_id = %s" \
    " AND c.usuario_id = %s" \
    " AND c.estadoPago = 'completado'", (partitura_id, usuario_id))

    compra = cursor.fetchone()

    if not compra:
        flash("No has comprado esta partitura.", "danger")
        return redirect(url_for("detalle_partitura", partitura_id=partitura_id))
    
    # Obtener nombre del PDF
    cursor.execute("SELECT url FROM imagenes WHERE partitura_id = %s", (partitura_id,))
    pdf_row = cursor.fetchone()
    conn.close()

    if not pdf_row:
        flash("No se encontró el archivo.", "danger")
        return redirect(url_for("index"))

    pdf_filename = pdf_row["url"]

    # Enviar archivo desde la carpeta privada
    return send_from_directory(os.path.join(os.getcwd(), "upload_pdfs"), pdf_filename, as_attachment=True)

@app.route('/carrito/agregar/<int:partitura_id>')
def agregar_al_carrito(partitura_id):
    if 'usuario_id' not in session:
        flash("Debes iniciar sesión para poder agregar elementos al carrito.")
        return redirect(url_for('login'))
    
    # Crear carrito si no existe. Será un conjunto de partituras
    carrito = session.get('carrito', {})
    
    # Aumentar cantidad
    carrito[str(partitura_id)] = session.get(str(partitura_id), 0) + 1

    session['carrito'] = carrito
    flash("Partitura añadida al carrito.", "success")
    return redirect(request.referrer or url_for("index"))

@app.route('/carrito')
def ver_carrito():
    carrito = session.get('carrito', {})

    if not carrito:
        return render_template('carrito.html', items=[], total=0)
    
    conn = get_db_connection()
    cursor = conn.cursor()

    ids = tuple(map(int, carrito.keys()))

    if len(ids) == 1:
        ids_sql = f"({ids[0]})"
    else:
        ids_sql = tuple(ids)

    sql = f"SELECT id, nombre, precio FROM partituras WHERE id IN {ids_sql}"
    cursor.execute(sql)
    partituras = cursor.fetchall()
    conn.close()

    items = []
    total = 0
    
    for p in partituras:
        cantidad = carrito[str(p['id'])]
        subtotal = cantidad * p['precio']
        total += subtotal

        items.append({
            'id': p['id'],
            'nombre': p['nombre'],
            'precio': p['precio'],
            'cantidad': cantidad,
            'subtotal': subtotal
        })

    return render_template('carrito.html', items=items, total=total)

@app.route("/carrito/eliminar/<int:partitura_id>")
def eliminar_del_carrito(partitura_id):
    carrito = session.get('carrito', {})
    carrito.pop(str(partitura_id), None)
    session['carrito'] = carrito
    flash("Partitura eliminada del carrito.", "success")
    return redirect(url_for('ver_carrito'))

@app.route("/carrito/vaciar")
def vaciar_carrito():
    session['carrito'] = {}
    flash("Carrito vaciado correctamente.", "success")
    return redirect(url_for('ver_carrito'))

@app.route("/checkout", methods=['GET', 'POST'])
def checkout():
    if 'usuario_id' not in session or not session.get('carrito'):
        flash("Debes iniciar sesión y tener al menos 1 producto en el carrito para proceder con la compra.", "danger")
        return redirect(url_for("index"))
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Obtener info. de las partituras que están dentro del carrito
    carrito_ids = list(session['carrito'].keys())
    format_strings = ','.join(['%s'] * len(carrito_ids))
    cursor.execute(f"SELECT id, nombre, precio FROM partituras WHERE id IN ({format_strings})", carrito_ids)
    partituras = cursor.fetchall()
    conn.close()

    total_compra = round(sum(float(p['precio']) * session['carrito'][str(p['id'])]  for p in partituras), 2)


    if request.method == "POST":
        # Cerrar sesión de pago en Stripe
        line_items = []
        for p in partituras:
            cantidad = session['carrito'][str(p['id'])]
            line_items.append({
                'price_data': {
                    'currency': 'eur',
                    'unit_amount': int(p['precio'] * 100),
                    'product_data': {
                        'name': p['nombre']
                    }
                },
                'quantity': cantidad
            })
        
        checkout_session = stripe.checkout.Session.create(
            payment_method_types = ['card'],
            line_items = line_items,
            mode = 'payment',
            success_url = url_for('checkout_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url = url_for('checkout_cancel', _external=True)
        )

        return redirect(checkout_session.url, code=303)
    return render_template('checkout.html', partituras=partituras, total_compra=total_compra, public_key=STRIPE_PUBLIC_KEY)

# Página de éxito
@app.route("/checkout/success")
def checkout_success():
    session_id = request.args.get("session_id")
    if not session_id:
        flash("No se pudo verificar el pago.", "danger")
        return redirect(url_for("index"))

    # Confirmar el pago con Stripe
    checkout_session = stripe.checkout.Session.retrieve(session_id)

    if checkout_session.payment_status != "paid":
        flash("El pago no ha sido completado correctamente.", "danger")
        return redirect(url_for("index"))

    usuario_id = session.get('usuario_id')
    carrito = session.get('carrito', {})

    if not usuario_id or not carrito:
        flash("Error al procesar la compra.", "warning")
        return redirect(url_for("index"))

    # Registrar la compra en la BD
    conn = get_db_connection()
    cursor = conn.cursor()

    carrito_ids = list(carrito.keys())
    format_strings = ','.join(['%s'] * len(carrito_ids))
    cursor.execute(f"SELECT id, precio FROM partituras WHERE id IN ({format_strings})", carrito_ids)
    partituras = cursor.fetchall()

    total_compra = sum(float(p['precio']) * carrito[str(p['id'])] for p in partituras)

    cursor.execute("""
        INSERT INTO compras (totalCompra, usuario_id, estadoPago)
        VALUES (%s, %s, 'completado')
    """, (total_compra, usuario_id))

    compra_id = cursor.lastrowid

    for partitura_id, cantidad in carrito.items():
        cursor.execute("""
            INSERT INTO lineasCompra (unidades, partitura_id, compra_id)
            VALUES (%s, %s, %s)
        """, (cantidad, partitura_id, compra_id))

    conn.commit()
    conn.close()

    session['carrito'] = {} # Vaciar el carrito

    # Descargar ZIP automáticamente
    return redirect(url_for('post_pago', compra_id=compra_id))


@app.route("/post_pago/<int:compra_id>")
def post_pago(compra_id):
    return render_template("post_pago.html", compra_id=compra_id)


# Página de cancelación
@app.route("/checkout/cancel")
def checkout_cancel():
    flash("Pago cancelado", "warning")
    return redirect(url_for("index"))

@app.route('/perfil')
def perfil():
    if 'usuario_id' not in session:
        flash("Debes iniciar sesión para ver tu perfil.", "warning")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT nombreUsuario, email, fotoPerfil FROM usuarios WHERE id=%s", (usuario_id,))
    usuario = cursor.fetchone()
    cursor.execute("SELECT c.id AS compra_id, c.totalCompra, c.fecha_compra, lc.unidades, p.nombre AS partitura_nombre," \
    " p.precio AS partitura_precio, img.thumbnail_url FROM compras c" \
    " JOIN lineasCompra lc ON lc.compra_id = c.id" \
    " JOIN partituras p ON p.id = lc.partitura_id" \
    " LEFT JOIN imagenes img ON img.partitura_id = p.id" \
    " WHERE c.usuario_id = %s" \
    " AND c.estadoPago = 'completado'" \
    " ORDER BY c.fecha_compra DESC", (usuario_id,))

    compras = cursor.fetchall()
    conn.close()
    
    return render_template('perfil.html', usuario=usuario, compras=compras)

    return render_template('perfil.html', usuario=usuario)


@app.route("/perfil/cambiar_contrasena", methods=["GET", "POST"])
def cambiar_contrasena():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        contrasena_actual = request.form["contrasena_actual"]
        contrasena_nueva = request.form["contrasena_nueva"]

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Obtener contraseña actual
        cursor.execute(
            "SELECT contrasenya FROM usuarios WHERE id = %s",
            (session["usuario_id"],)
        )
        usuario = cursor.fetchone()

        # Comprobar hash
        if not check_password_hash(usuario["contrasenya"], contrasena_actual):
            flash("La contraseña actual no es correcta.", "danger")
            return redirect(url_for("cambiar_contrasena"))

        # Guardar nueva contraseña
        nueva_hash = generate_password_hash(contrasena_nueva)
        cursor.execute(
            "UPDATE usuarios SET contrasenya = %s WHERE id = %s",
            (nueva_hash, session["usuario_id"])
        )
        conn.commit()
        conn.close()

        flash("Contraseña cambiada correctamente.", "success")
        return redirect(url_for("perfil"))

    return render_template("cambiar_contrasena.html")


@app.route("/perfil/cambiar_foto", methods=["GET", "POST"])
def cambiar_foto():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        archivo = request.files.get("fotoPerfil")

        if not archivo or archivo.filename == "":
            flash("Debes seleccionar una imagen.", "warning")
            return redirect(url_for("cambiar_foto"))

        # Guardar archivo
        nombre_archivo = secure_filename(archivo.filename)
        ruta_relativa = f"images/perfiles/{session['usuario_id']}_{nombre_archivo}"
        ruta_absoluta = os.path.join("static", ruta_relativa)

        archivo.save(ruta_absoluta)

        # Actualizar en BD
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE usuarios SET fotoPerfil = %s WHERE id = %s",
            (ruta_relativa, session["usuario_id"])
        )
        conn.commit()
        conn.close()

        # Actualizar sesión
        session["usuario_foto"] = ruta_relativa

        flash("Foto de perfil actualizada correctamente.", "success")
        return redirect(url_for("perfil"))

    return render_template("cambiar_foto.html")

def obtener_carrito(usuario_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT id FROM carritos WHERE usuario_id=%s", (usuario_id,))
    carrito = cursor.fetchone()
    
    if not carrito:
        cursor.execute("INSERT INTO carritos(usuario_id) VALUES (%s)", (usuario_id,))
        conn.commit()
        carrito_id = cursor.lastrowid
    else:
        carrito_id = carrito["id"]
    
    conn.close()
    return carrito_id

@app.route("/agregar_carrito/<int:partitura_id>")
def agregar_carrito(partitura_id):
    usuario_id = session.get("usuario_id")
    if not usuario_id:
        flash("Debes iniciar sesión para añadir al carrito", "danger")
        return redirect(url_for("login"))
    
    carrito_id = obtener_carrito(usuario_id)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, cantidad FROM lineasCarrito WHERE carrito_id=%s AND partitura_id=%s",
        (carrito_id, partitura_id)
    )
    item = cursor.fetchone()
    
    if item:
        cursor.execute(
            "UPDATE lineasCarrito SET cantidad=cantidad+1 WHERE id=%s",
            (item[0],)
        )
    else:
        cursor.execute(
            "INSERT INTO lineasCarrito(carrito_id, partitura_id, cantidad) VALUES (%s,%s,1)",
            (carrito_id, partitura_id)
        )
    
    conn.commit()
    conn.close()
    flash("Partitura añadida al carrito", "success")
    return redirect(url_for("catalogo"))

def cargar_carrito_en_sesion(usuario_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT c.partitura_id, c.cantidad FROM lineasCarrito c "
                   "JOIN carritos ca ON ca.id=c.carrito_id "
                   "WHERE ca.usuario_id=%s", (usuario_id,))
    items = cursor.fetchall()
    conn.close()
    
    session['carrito'] = { str(item['partitura_id']): item['cantidad'] for item in items }

def guardar_carrito_desde_sesion(usuario_id):
    carrito_id = obtener_carrito(usuario_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Limpiar carrito actual en BD
    cursor.execute("DELETE FROM lineasCarrito WHERE carrito_id=%s", (carrito_id,))
    
    # Guardar items de session
    for partitura_id, cantidad in session.get('carrito', {}).items():
        cursor.execute(
            "INSERT INTO lineasCarrito(carrito_id, partitura_id, cantidad) VALUES (%s,%s,%s)",
            (carrito_id, partitura_id, cantidad)
        )
    conn.commit()
    conn.close()


@app.route('/historial')
def historial_compras():
    if 'usuario_id' not in session:
        flash("Debes iniciar sesión para ver tu historial.", "warning")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']

    # Leer filtros
    orden = request.args.get('orden', 'fecha_desc')
    fecha = request.args.get('fecha')

    # Orden seguro
    if orden == 'fecha_asc':
        order_clause = "c.fecha_compra ASC"
    else:
        order_clause = "c.fecha_compra DESC"
        orden = "fecha_desc"

    # Construcción dinámica del WHERE
    where_clauses = ["c.usuario_id = %s", "c.estadoPago = 'completado'"]
    params = [usuario_id]

    if fecha:
        where_clauses.append("DATE(c.fecha_compra) = %s")
        params.append(fecha)

    where_sql = " AND ".join(where_clauses)

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute(f"""
        SELECT 
            c.id AS compra_id,
            c.totalCompra,
            c.fecha_compra,
            lc.unidades,
            p.nombre AS partitura_nombre,
            p.precio AS partitura_precio,
            img.thumbnail_url
        FROM compras c
        JOIN lineasCompra lc ON lc.compra_id = c.id
        JOIN partituras p ON p.id = lc.partitura_id
        LEFT JOIN imagenes img ON img.partitura_id = p.id
        WHERE {where_sql}
        ORDER BY {order_clause}
    """, params)

    compras = cursor.fetchall()
    conn.close()

    return render_template('historial.html', compras=compras, orden=orden, fecha=fecha)


@app.route('/partituras-subidas')
def partituras_subidas():
    if "usuario_id" not in session:
        return redirect(url_for('login'))

    usuario_id = session["usuario_id"]

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute("""
        SELECT id, nombre, precio, fecha, descripcion
        FROM partituras
        WHERE usuario_id = %s
        ORDER BY fecha DESC
    """, (usuario_id,))

    partituras = cursor.fetchall()
    conn.close()

    return render_template("partituras_subidas.html", partituras=partituras)


@app.route('/editar-partitura/<int:partitura_id>', methods=['GET', 'POST'])
def editar_partitura(partitura_id):
    if "usuario_id" not in session:
        return redirect(url_for('login'))

    usuario_id = session["usuario_id"]

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute("""
        SELECT * FROM partituras WHERE id = %s AND usuario_id = %s
    """, (partitura_id, usuario_id))
    partitura = cursor.fetchone()

    if not partitura:
        conn.close()
        return "No tienes permiso para editar esta partitura", 403

    if request.method == "POST":
        nombre = request.form["nombre"]
        precio = request.form["precio"]
        descripcion = request.form["descripcion"]

        cursor.execute("""
            UPDATE partituras
            SET nombre=%s, precio=%s, descripcion=%s
            WHERE id=%s AND usuario_id=%s
        """, (nombre, precio, descripcion, partitura_id, usuario_id))
        conn.commit()
        conn.close()

        return redirect(url_for("partituras_subidas"))

    conn.close()
    return render_template("editar_partitura.html", partitura=partitura)


@app.route('/eliminar-partitura/<int:partitura_id>', methods=['POST', 'GET'])
def eliminar_partitura(partitura_id):
    if "usuario_id" not in session:
        return redirect(url_for('login'))

    usuario_id = session["usuario_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM partituras
        WHERE id = %s AND usuario_id = %s
    """, (partitura_id, usuario_id))

    if not cursor.fetchone():
        conn.close()
        return "No tienes permiso para eliminar esta partitura.", 403

    cursor.execute("DELETE FROM partituras WHERE id = %s", (partitura_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("partituras_subidas"))

@app.route('/descargar_compra/<int:compra_id>')
def descargar_compra(compra_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute("""
        SELECT p.nombre, i.url 
        FROM lineasCompra lc
        JOIN partituras p ON lc.partitura_id = p.id
        JOIN imagenes i ON p.id = i.partitura_id
        WHERE lc.compra_id = %s
    """, (compra_id,))
    partituras = cursor.fetchall()
    conn.close()

    if not partituras:
        return redirect(url_for("index"))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        for p in partituras:
            ruta_archivo = p["url"]
            nombre_archivo = p["nombre"] + os.path.splitext(ruta_archivo)[1]
            zipf.write('upload_pdfs/' + ruta_archivo, arcname=nombre_archivo)

    buffer.seek(0)
    response = make_response(buffer.read())
    response.headers.set('Content-Type', 'application/zip')
    response.headers.set('Content-Disposition', 'attachment', filename="partituras_compradas.zip")

    # ⬇️ Truco: redirigir después de comenzar descarga
    response.headers.set("Refresh", "1; url=" + url_for('index'))

    return response



if __name__ == '__main__':
    app.run(debug=True)