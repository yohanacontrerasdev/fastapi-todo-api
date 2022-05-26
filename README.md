# Parte 1: Cómo crear una API REST COMPLETA con FastAPI, instalación y estructura

## Que vamos a aprenderemos

En esta serie de tutoriales veremos como crear la estructura del proyecto, usar la autenticación con JWT, enrutamiento, conexiones a bases de datos y realizaremos tests para verificar el correcto funcionamiento de la aplicación.

## De que va el proyecto

El proyecto que vamos a realizar será una herramienta en la que podremos crear un usuario y este podrá tener un listado de tareas por hacer (también conocido como to-do list). Este podrá crearlas y después marcarlas como hechas

## Crear proyecto y entorno virtual e instalar FastAPI

Lanzamos el comando para crear el entorno virtual:

```python
python -m venv env
```
Y después lo activamos:

```python
# Windows
.\env\Scripts\activate
# Mac/linux
source env/bin/activate
```

Una vez hecho, instalaremos FastAPI y uvicorn que os explicaré a continuación que es y para qué lo utilizaremos:

```python
pip install fastapi uvicorn
```
Uvicorn es un servidor ASGI de alto rendimiento que usaremos para correr nuestra aplicación

Para ver nuestra API en funcionamiento, vamos a la terminal y lanzamos el siguiente comando:

```python
uvicorn main:app --reload
```

El comando uvicorn recibe un parámetro y una flag. El parámetro indica el nombre del archivo que queremos correr, después añadimos dos puntos y le indicamos el nombre de la variable que definimos como instancia de FastAPI.

El flag --reload hará que cada vez que ejecutemos un cambio en nuestro proyecto y guardemos, se recargue el proceso de uvicorn y se reflejen nuestros cambios en la API.

# Parte 2: Conexiones a bases de datos y creación de modelos con FastAPI

 En el tutorial de esta semana vamos a aprender cómo crear una conexión a nuestra base de datos PostgreSQL gracias a la librería peewee. También crearemos los modelos que nos permitirán generar nuestras tablas y que después utilizaremos también para poder realizar consultas a la base de datos.

Una vez instalado PostgreSQL, vamos a crear nuestra base de datos. Para ello accedéis a PostgreSQL y una vez dentro, lanzáis el siguiente comando que generará la base de datos:

```sql
 CREATE DATABASE to_do_list WITH OWNER = <your-database-user> ENCODING = 'UTF8' CONNECTION LIMIT = -1;
 ```
## Variables de entorno y settings

Ahora que tenemos la base de datos, ya podemos empezar a trabajar con ella desde nuestro proyecto. Para ello, primero vamos a guardar la información sobre la autenticación a la base de datos en el archivo .env que generamos en el tutorial anterior. Este archivo contendrá pares de clave-valor en el que deberéis reemplazar los valores de autenticación y conexión a la base de datos por los vuestros. Ejemplo:

# Database connection

```
DB_NAME=to_do_list
DB_USER=my-user
DB_PASS=my-pass
DB_HOST=localhost
DB_PORT=5432
```

El siguiente paso es instalar la librería python-dotenv que cargará automáticamente las variables de entorno que hemos generado en el archivo .env. Gracias a esto, podremos usarlas dentro de nuestro proyecto.

```
pip install python-dotenv
```

## Librería pydantic

Antes de seguir, vamos a explicar que es la librería pydantic, ya que en FastAPI la vamos a utilizar a menudo. Pydantic es una librería de Python la cual se encarga de realizar validaciones de datos, es decir que si por ejemplo creamos una clase extendiendo de una clase Base de pydantic y en ella declaramos una variable de tipo string (pydantic nos fuerza a asignar un tipo cada vez que declaramos una variable), si luego creamos una instancia de esta clase e intentamos asignar un valor de tipo booleano a esa variable, esta lanzará una excepción indiciando que el tipo de dato es erróneo.

Una vez explicado esto seguimos. Ahora vamos a emplear la clase BaseSettings de pydantic. Esta clase la emplearemos para guardar la configuración de nuestro proyecto como por ejemplo las variables de entorno que creamos hace un momento.

Para ello, vamos al directorio /app/v1/utils y dentro de él, generamos un archivo llamado settings.py que contendrá el siguiente código:

```python
import os

from pydantic import BaseSettings
from dotenv import load_dotenv
load_dotenv()


class Settings(BaseSettings):

    db_name: str = os.getenv('DB_NAME')
    db_user: str = os.getenv('DB_USER')
    db_pass: str = os.getenv('DB_PASS')
    db_host: str = os.getenv('DB_HOST')
    db_port: str = os.getenv('DB_PORT')
```

Primero importamos las librerías que necesitaremos, en este caso os para poder leer las variables de entorno, la clase BaseSettings y la función load_dotenv de la librería python-dotenv la cual se encargará de leer las variables de entorno.

Después declaramos la clase Settings que extenderá de BaseSettings y para finalizar declaramos las variables que guardarán la información sobre la conexión y autenticación a la base de datos.

Los valores los asignamos gracias a la función getenv de la librería os la cual recibe el nombre que les dimos a las variables de entorno en el archivo .env y si existen retornan su valor. Si no es así, devolverá None.

### Conexión a la base de datos

Ahora que ya podemos leer las variables de entorno, es hora de conectarnos a la base de datos. Para ello primero vamos a instalar peewee, ya que será el ORM que vamos a utilizar en este proyecto y psycopg2 que es la librería que hace de puente entre PostgreSQL y Python:

```
pip install psycopg2
pip install peewee
```

Una vez instaladas las librerías nos dirigimos de nuevo al directorio /app/v1/utils y generamos un archivo llamado db.py, este contendrá el siguiente código:

```python
import peewee
from contextvars import ContextVar
from fastapi import Depends

from app.v1.utils.settings import Settings

settings = Settings()

DB_NAME = settings.db_name
DB_USER = settings.db_user
DB_PASS = settings.db_pass
DB_HOST = settings.db_host
DB_PORT = settings.db_port


db_state_default = {"closed": None, "conn": None, "ctx": None, "transactions": None}
db_state = ContextVar("db_state", default=db_state_default.copy())

class PeeweeConnectionState(peewee._ConnectionState):
    def __init__(self, **kwargs):
        super().__setattr__("_state", db_state)
        super().__init__(**kwargs)

    def __setattr__(self, name, value):
        self._state.get()[name] = value

    def __getattr__(self, name):
        return self._state.get()[name]


db = peewee.PostgresqlDatabase(DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)

db._state = PeeweeConnectionState()

async def reset_db_state():
    db._state._state.set(db_state_default.copy())
    db._state.reset()


def get_db(db_state=Depends(reset_db_state)):
    try:
        db.connect()
        yield
    finally:
        if not db.is_closed():
            db.close()
```

Este archivo básicamente es una copia del tutorial de FastAPI para realizar la conexión con peewee. Lo que estamos haciendo primero es crear una instancia de clase Settings que creamos unos pasos más atrás y después guardar las variables de entorno de la conexión en constantes.

Posteriormente, sobreescribimos la clase PeeweeConnectionState, esto se hace por el asincronismo y está mejor explicado en el tutorial de FastAPI que os he dejado en el párrafo anterior.

El siguiente paso es efectuar la conexión a la base de datos de PostgreSQL, aquí es donde empleamos los parámetros de autenticación y conexión.

Por último, las funciones reset_db_state y get_db las utilizaremos para poder utilizar la conexión a la base de datos en todo nuestro proyecto. También podéis encontrar más información acerca de estas funciones en el tutorial de FastAPI que os dejé antes.

## Creación de modelos

Ahora que ya tenemos la conexión a la base de datos es hora de crear los modelos de peewee, estos los usaremos para nuestras tablas en la base de datos y también para poder realizar consultas, insertar datos, actualizarlos, etc.

Nuestra base de datos constará de dos tablas, una para almacenar los usuarios llamada user y otra tabla llamada todo que almacenará las tareas hechas y por hacer de un usuario.

El primer modelo que vamos a crear será el de usuarios. Para ello vamos al directorio /app/v1/model y creamos un archivo llamado user_model.py:

```python
import peewee

from app.v1.utils.db import db

class User(peewee.Model):
    email = peewee.CharField(unique=True, index=True)
    username = peewee.CharField(unique=True, index=True)
    password = peewee.CharField()

    class Meta:
        database = db
```

Esta clase extiende de peewee.Model y en ella declaramos los campos que vamos a necesitar que será un email, username y password. El id no es necesario definirlo, ya que peewee se encargará de crearlo automáticamente como clave primaria y autoincrement.

Después añadimos la clase Meta dentro de la clase User que contendrá la conexión a la base de datos.

Si queréis más información acerca de que tipos de datos podéis crear con peewe os dejo el enlace a su documentación.

El siguiente modelo es el modelo todo. Para ello en la misma carpeta creamos un archivo llamado todo_model.py con el siguiente contenido:

```python
from datetime import datetime

import peewee

from app.v1.utils.db import db
from .user_model import User


class Todo(peewee.Model):
    title = peewee.CharField()
    created_at = peewee.DateTimeField(default=datetime.now)
    is_done = peewee.BooleanField(default=False)
    user = peewee.ForeignKeyField(User, backref="todos")

    class Meta:
        database = db
```

En este caso tendremos cuatro columnas (más el id que se genera automáticamente). El campo title será una breve descripción de la tarea a realizar, created_at será la fecha de creación, un booleano llamado is_done para indicar si la tarea ya ha sido realizada o no que por defecto se guardará como false y una clave foránea user para indicar a que usuario corresponde el todo. Esto guardará en la base de datos como un campo llamado user_id.

Por último, vamos a generar un script que se encargará de crear las tablas. Para ello vamos al directorio /app/v1/scripts y dentro creamos un archivo llamado create_tables.py con el siguiente contenido:

```python
from app.v1.model.user_model import User
from app.v1.model.todo_model import Todo

from app.v1.utils.db import db

def create_tables():
    with db:
        db.create_tables([User, Todo])
```

En este archivo importamos los modelos User y Todo además del objeto de la base de datos y después definimos una función que se conectará a la base de datos, recibirá una lista de los modelos que queremos convertir en tablas y después cerrará la conexión.

Para ejecutar este script, en la terminal vamos al directorio raíz de nuestro proyecto y escribimos py o python para acceder a la terminal de Python y poder ejecutar código en este lenguaje.

Una vez dentro de la terminal, escribimos la siguiente línea para importar la función que acabamos de crear y pulsamos enter:

```python
from app.v1.scripts.create_tables import create_tables
```

Una vez importada nuestra función solo debemos ejecutarla, para ello escribimos el nombre de la función más paréntesis y pulsamos enter (ejecutar una función de toda la vida vamos):

```python
create_tables()
```

Listo, si todo ha ido bien ya deberíamos tener creadas nuestras tablas en la base de datos.

# Parte 3: Creación de modelos de Pydantic y nuestro primer usuario con FastAPI

En esta tercera parte vamos a ver cómo realizar el enrutamiento desde un archivo diferente al main, añadiremos los modelos de Pydantic y crearemos nuestro primer usuario con FastAPI

## Crear modelos de Pydantic

Como comentamos en el tutorial anterior, **Pydantic** es una librería de **Python** que se utiliza para la validación de datos. Como FastAPI dice en su **documentación**, este está basado en Pydantic así que será vital conocer su funcionamiento.

Por eso, antes de seguir voy a comentar en que casos nos será útil usar **Pydantic**:

- Definir requerimientos en la petición cuando nos envíen parámetros ya sea vía get, post, cabeceras, etc.
- Convertir los datos recibidos en el tipo requerido. Por ejemplo si enviamos vía get un parámetro llamado is_done que será igual a true (ejemplo: http://localhost:8000/todo?is_done=true), nosotros lo recibiremos como string y Pydantic se encargará de convertirlo a booleano.
- Validación de datos. Por ejemplo si necesitamos recibir un parámetro de tipo int validar que sea un número y si no lo es devolver un error en la respuesta.
- Documentación. Una de las mejores cosas de FastAPI es que genera una página de documentación de forma automática. Desde los modelos de Pydantic (y en otras partes también) podemos definir información adicional como vamos a ver en este tutorial.

Dicho esto vamos a crear nuestro primer modelo de Pydantic. Para diferenciarlos de los modelos de peewee, estos los vamos a guardar en la carpeta /app/v1/schema y el único modelo que necesitamos de momento es de usuarios así que nos dirigimos a esa carpeta y creamos un archivo que se llamará user_schema.py y que contendrá el siguiente código:

```python
from pydantic import BaseModel
from pydantic import Field
from pydantic import EmailStr


class UserBase(BaseModel):
    email: EmailStr = Field(
        ...,
        example="myemail@cosasdedevs.com"
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        example="MyTypicalUsername"
    )


class User(UserBase):
    id: int = Field(
        ...,
        example="5"
    )


class UserRegister(UserBase):
    password: str = Field(
        ...,
        min_length=8,
        max_length=64,
        example="strongpass"
    )
```

Como podéis observar, primero importamos **BaseModel** de **Pydantic** (bueno los tres imports son de Pydantic). Como explicamos anteriormente, todas las variables que definamos dentro de la clase que extienda de **BaseModel**, pasará por un proceso de validación y si hay algún error lanzará una excepción.

Después importamos la función Field. Esta función nos permite validar distintos tipos de datos, marcar si es obligatorio o no, tamaños máximos y mínimos, etc.

Por último importamos **EmailStr**. Esta clase la utilizaremos para tipar una variable como tipo email y validará si el email recibido es válido o no. Actualmente, hay que hacer una instalación adicional para usar esta clase así que lo haremos con el siguiente comando:

```python
pip install "pydantic[email]"
```

Posteriormente, tenemos tres modelos, el primero **UserBase** extenderá de **BaseModel** y será compartido por los otros dos y luego tenemos **User** que aparte de los parámetros base tendrá el id. Este modelo lo emplearemos como respuesta cuando necesitemos retornar la información de un usuario.

Por último tenemos **UserRegister** que lo emplearemos como modelo cuando un usuario se quiera registrar.

Ahora vamos a explicar la clase UserBase en profundidad:

Primero definimos la variable que será de tipo **EmailStr** y será igual a **Field**. Como primer parámetro enviamos **"..."** que significa que **ese campo será obligatorio**, como segundo parámetro recibe **example** que es un dato informativo para el usuario y que podremos ver en la documentación más adelante.

La segunda variable es **username**. Esta será de tipo **string** y aquí recibe dos parámetros nuevos que son **min_length** y **max_length**. Esto significa que el string necesitará tener al menos 3 caracteres y como máximo 50 (o los que definamos nosotros) para ser válido. Si no es así la validación de Pydantic lanzará un error.

Si queréis más información acerca de las distintas validaciones que podéis utilizar según los tipos, os dejo el enlace a la doc de Pydantic.

### Crear nuestro primer usuario

Ahora que ya tenemos un modelo para los usuarios, vamos a crear nuestro primer usuario. Para ello necesitaremos la información del usuario y un sistema para encriptar la contraseña. Recordad, nunca debemos tener en la base de datos las contraseñas de nuestros usuarios en texto plano.

Para encriptar la contraseña utilizaremos la librería passlib con el algoritmo de Bcrypt. Para instalarla lanzamos el siguiente comando:

```
pip install "passlib[bcrypt]"
```

Una vez instalada, vamos a ir al directorio /app/v1/service y crearemos un archivo llamado user_service.py con el siguiente contenido:

```python
from fastapi import HTTPException, status

from passlib.context import CryptContext

from app.v1.model.user_model import User as UserModel
from app.v1.schema import user_schema


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def create_user(user: user_schema.UserRegister):

    get_user = UserModel.filter((UserModel.email == user.email) | (UserModel.username == user.username)).first()
    if get_user:
        msg = "Email already registered"
        if get_user.username == user.username:
            msg = "Username already registered"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg
        )

    db_user = UserModel(
        username=user.username,
        email=user.email,
        password=get_password_hash(user.password)
    )

    db_user.save()

    return user_schema.User(
        id = db_user.id,
        username = db_user.username,
        email = db_user.email
    )
```

En este archivo primero importamos **HTTPException** y **status** de **FastAPI**. La primera la usaremos cuando queramos lanzar una excepción controlada por **FastAPI**. Si lanzamos esta excepción, podremos customizar una respuesta para el usuario en formato JSON y con un **código de estado de HTTP**.

**Status** de **FastAPI contiene los códigos de estado HTTP** almacenados en constantes en el que en los nombres de las constantes tendremos información del significado del código de estado. Esto lo utilizaremos cuando queramos lanzar una excepción de tipo **HTTPException**.

Después importamos **CryptContext** que será la librería que emplearemos para **encriptar las contraseñas**.

Por último importamos nuestro modelo de usuario de **peewee** para poder crear el usuario y el modelo de usuario de **Pydantic** para retornar al usuario la información del usuario creado.

Ahora que hemos explicado los imports vamos con la siguiente parte del código. Primero creamos una instancia de **CryptContext** y posteriormente definimos una función llamada **get_password_hash** que encriptará la contraseña **utilizando la instancia de CryptContext** que acabamos de crear.

La siguiente función se llama **create_user** y recibe un modelo de Pydantic de tipo **UserRegister**. Esta función se encargará de guardar el usuario en la base de datos. Comprobamos si el usuario enviado ya existe en la base de datos por email o por username, si es así, lanzaremos una excepción **HTTPException** con el código de estado 400 y en el detail explicaremos el porqué del error.

Después usando el modelo de usuario de **peewee**, creamos el usuario con la contraseña encriptada y lo guardamos.

Por último retornamos la información del usuario recién creado empleando **el modelo User de Pydantic.**

### Ruta para la creación de usuarios

Ya tenemos una función que nos permitirá crear usuarios, pero todavía no tenemos un endpoint que apunte a esta función. Don't worry porque lo vamos a crear ahora mismo.

Para realizar este paso, vamos a la carpeta /app/v1/router y generamos un archivo llamado user_router.py que contendrá el siguiente código:

```python
from fastapi import APIRouter
from fastapi import Depends
from fastapi import status
from fastapi import Body

from app.v1.schema import user_schema
from app.v1.service import user_service

from app.v1.utils.db import get_db


router = APIRouter(prefix="/api/v1")

@router.post(
    "/user/",
    tags=["users"],
    status_code=status.HTTP_201_CREATED,
    response_model=user_schema.User,
    dependencies=[Depends(get_db)],
    summary="Create a new user"
)
def create_user(user: user_schema.UserRegister = Body(...)):
    """
    ## Create a new user in the app

    ### Args
    The app can recive next fields into a JSON
    - email: A valid email
    - username: Unique username
    - password: Strong password for authentication

    ### Returns
    - user: User info
    """
    return user_service.create_user(user)
```

Primero importamos **APIRouter**. Este **nos permitirá crear rutas a nuestra API de forma separada del archivo main.py.**

Luego importamos **Depends** y **status** que ya las conocemos y el último import que realizamos de **FastAPI** será **Body.** Utilizaremos esta función para recuperar la información que nos envíe el usuario en la petición para crear el usuario.

Seguidamente, importamos los modelos de **Pydantic** de usuarios y el servicio de usuarios que creamos anteriormente.

Por último, importamos la conexión a la base de datos.

Una vez hecho esto, generamos una instancia de la clase **APIRouter** con el parámetro **prefix que será igual /api/v1.** Esto significará que todas las rutas que creemos con esa instancia tendrán como prefijo esa url.

El segundo parámetro es **tags** que será una lista con un valor llamado **users**. A nivel de código no implica nada, pero nos servirá para agrupar nuestros endpoints por tipo cuando más adelante veamos el funcionamiento de la documentación que genera FastAPI automáticamente.

Ahora que ya tenemos la instancia de APIRouter configurada es hora de añadir **nuestro primer endpoint.** Para ello, al igual que cuando definimos el endpoint para retornar el mensaje "Hello world", creamos un decorador con router.

Indicamos que la petición será de tipo post usando él (valga la redundancia) **método post de router** y como parámetros recibirá varios parámetros.

El primer parámetro serla la ruta que nosotros la llamaremos "/user/" y **que realmente como añadimos un prefijo en la instancia de APIRouter será /api/v1/user/.**

El siguiente parámetro sería **status_code** que es el estado **HTTP** que queremos devolver en nuestro endpoint. Es un campo opcional y si no lo añadimos **por defecto será el estado 200 OK**, pero como lo que vamos a hacer es crear un dato, lo modificaremos y usaremos el estado 201.

El parámetro response_model indicará que la respuesta que retornaremos será **un modelo de Pydantic de tipo User.**

Como **dependencies** pasamos la conexión a la base de datos, ya que la necesitaremos para crear al usuario.

Y por último, el parámetro **summary** será informativo para la documentación.

Ahora que terminamos con el decorador, definimos la función. Esta recibirá una variable llamada user y que será de tipo **UserRegister** e igual a Body. Como cuando creamos los datos del modelo de Pydantic y Field, en el caso de que Body recibirá por parámetro "..." Significará que el campo es obligatorio.

Dentro de la función he definido un bloque de documentación. En este bloque podremos utilizar sintaxis de Markdown que FastAPI interpretará y podremos ver en la documentación. Yo lo he hecho con el formato que veis, pero podéis hacerla como queráis.

Al final llamamos a la función create_user que definimos en el archivo user_service.py y enviamos por parámetro la variable user. Esta retornará el modelo User de Pydantic que definimos en user_schema.py.

Lo siguiente que haremos serán modificaciones en el archivo main.py. Abrimos el archivo y realizamos los siguientes cambios:

```python
from fastapi import FastAPI

from app.v1.router.user_router import router as user_router

app = FastAPI()

app.include_router(user_router)
```

El primer cambio que podéis ver es que hemos importado el router que acabamos de crear. Luego de instanciar FastAPI incluimos el router de usuario dentro de la app gracias al método include_router. Esto nos permitirá añadir rutas a nuestro proyecto desde otros archivos (como user_router).

Por último, he eliminado el endpoint que creamos de ejemplo, ya que no lo necesitaremos.

Listo, ya podemos probar nuestra API. Para ello levantamos el server si no lo hemos hecho y en nuestro navegador nos dirigimos a la siguiente url: http://127.0.0.1:8000/docs

# Parte 4: Autenticación con JWT en FastAPI

### Modelo de Pydantic para los tokens

Lo primero que vamos a necesitar es un modelo para los tokens. Para ello vamos a la carpeta /app/v1/schema y creamos un archivo llamado token_schema.py que contendrá el siguiente código:

```python
from pydantic import BaseModel
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
```

En este caso tendremos la clase Token que será el objeto que usaremos para retornarle el token de autenticación y el tipo de autenticación y luego tendremos una clase TokenData que almacenará el nombre de usuario en el token. Aquí podríamos guardar más información que nos podría ser útil en el token y cuando lo decodificásemos poder utilizarla.

Como podéis observar, aquí empleamos un tipo nuevo llamado Optional que recibe el tipo de dato e indica que ese campo será opcional. En este caso no estamos usando Field y por defecto le daremos un valor de None.

### Nuevas variables de entorno

Ahora que ya tenemos nuestro modelo para los tokens, el siguiente paso será crear un para de variables de entorno llamadas ACCESS_TOKEN_EXPIRE_MINUTES y SECRET_KEY. La primera contendrá el tiempo de validez máximo de un token en minutos y la segunda una clave para codificar y decodificar nuestros tokens. Si estáis en Linux esta clave podéis generarla con el siguiente comando:

```python
openssl rand -hex 32
```

si no estas en linux:

```
Abrís el archivo .env y añadís las variables:


# Auth
ACCESS_TOKEN_EXPIRE_MINUTES=1440
SECRET_KEY=e97965045c7df14cb4d5760371e7325104a8f33ad5d00c0
```

Como tiempo de expiración yo le he dado 24 horas, sin embargo, podéis darle el tiempo que queráis.

Ahora abrimos el archivo /app/v1/utils/settings.py y añadimos las nuevas variables:

```python
import os

from pydantic import BaseSettings
from dotenv import load_dotenv
load_dotenv()


class Settings(BaseSettings):

    db_name: str = os.getenv('DB_NAME')
    db_user: str = os.getenv('DB_USER')
    db_pass: str = os.getenv('DB_PASS')
    db_host: str = os.getenv('DB_HOST')
    db_port: str = os.getenv('DB_PORT')

    secret_key: str = os.getenv('SECRET_KEY')
    token_expire: int = os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES')
```

### Autenticación
Una vez añadidas las nuevas variables de entorno al proyecto es hora de ponernos manos a la obra con la autenticación. Para ello, primero vamos a instalar librería que usaremos para trabajar con JWT así que lanzamos el siguiente comando para instalarla:

```
pip install "python-jose[cryptography]"
```

También necesitaremos instalar python-multipart. Para ello lanzamos el siguiente comando:

```
pip install python-multipart
```

Una vez hecho esto, vamos a crear un archivo llamado auth_service.py dentro de /app/v1/service y vamos a añadir el siguiente contenido:

```python
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.v1.model.user_model import User as UserModel
from app.v1.schema.token_schema import TokenData
from app.v1.utils.settings import Settings

settings = Settings()


SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.token_expire


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/login")


def verify_password(plain_password, password):
    return pwd_context.verify(plain_password, password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    return UserModel.filter((UserModel.email == username) | (UserModel.username == username)).first()


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def generate_token(username, password):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user
```

De lo imports nuevos podemos ver datetime que lo utilizaremos para darle un tiempo de vida al token.

También está OAuth2PasswordBearer que lo usaremos para indicar la url de login y para validar el token.

Y por último la librería jose para validar y generar los tokens con JWT.

Después definimos tres constantes en las que guardamos la clave secreta, el algoritmo de codificación y el tiempo de vida del token.

En las siguientes líneas volvemos a usar pwd_context que nos servirá para verificar la validez del password y para generar un hash a partir del password. Una vez explique todo el auth_service.py eliminaremos esa parte del user_service.py para no tenerla duplicada.

Creamos una instancia de OAuth2PasswordBearer y por parámetro definimos la url a la que tendrá que acceder nuestro usuario para poder hacer login.

Luego tenemos las funciones verify_password y get_password_hash para validar un password y para generar un hash de él (que es lo que guardamos como password en la base de datos).

La siguiente función que tenemos es get_user que puede recibir un username o email, esto lo hacemos así para poder autenticarnos tanto por el username como por el email. Retornamos el usuario si existe.

Posteriormente, tenemos la función authenticate_user que recibe un username y el password y comprueba que exista, si es así, verifica que el password es correcto.

La función create_access_token recibe un diccionario con la información que queremos guardar en el token y el tiempo de expiración de este y después lo genera con la función jwt.encode que recibe por parámetro la información a guardar, nuestra clave secreta y el algoritmo que utilizaremos.

Seguidamente, tenemos la función generate_token la cual llamada a la función authenticate_user para revisar la validez de los datos enviados. Si no es así lanzará una excepción y si todo ha ido bien llamará a la función create_access_token y retornará el token del usuario.

Por último tenemos la función get_current_user que recibe un token por parámetro y retorna la información del usuario si es válido.

Ahora que hemos explicado el auth_service.py, vamos a eliminar el código duplicado en el archivo user_service.py, ya que en auth_service.py tenemos también la función get_password_hash y tiene más sentido que esté ahí así que abrimos el archivo y sustituimos nuestro código por el siguiente:

```python
from fastapi import HTTPException, status

from app.v1.model.user_model import User as UserModel
from app.v1.schema import user_schema
from app.v1.service.auth_service import get_password_hash


def create_user(user: user_schema.UserRegister):

    get_user = UserModel.filter((UserModel.email == user.email) | (UserModel.username == user.username)).first()
    if get_user:
        msg = "Email already registered"
        if get_user.username == user.username:
            msg = "Username already registered"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg
        )

    db_user = UserModel(
        username=user.username,
        email=user.email,
        password=get_password_hash(user.password)
    )

    db_user.save()

    return user_schema.User(
        id = db_user.id,
        username = db_user.username,
        email = db_user.email
    )
```

Lo único que hemos hecho es eliminar la función get_password_hash, el import de CryptContext y la instancia de este para importar get_password_hash de auth_service.py.

Listo, ya tenemos todo casi preparado, ahora solo falta definir la ruta del login en el archivo /app/v1/router/user_route.py así que lo abrimos y sustituimos el código existente por este:

```python
from fastapi import APIRouter
from fastapi import Depends
from fastapi import status
from fastapi import Body
from fastapi.security import OAuth2PasswordRequestForm

from app.v1.schema import user_schema
from app.v1.service import user_service
from app.v1.service import auth_service
from app.v1.schema.token_schema import Token

from app.v1.utils.db import get_db


router = APIRouter(
    prefix="/api/v1",
    tags=["users"]
)

@router.post(
    "/user/",
    status_code=status.HTTP_201_CREATED,
    response_model=user_schema.User,
    dependencies=[Depends(get_db)],
    summary="Create a new user"
)
def create_user(user: user_schema.UserRegister = Body(...)):
    """
    ## Create a new user in the app

    ### Args
    The app can receive next fields into a JSON
    - email: A valid email
    - username: Unique username
    - password: Strong password for authentication

    ### Returns
    - user: User info
    """
    return user_service.create_user(user)

@router.post(
    "/login",
    tags=["users"],
    response_model=Token
)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    ## Login for access token

    ### Args
    The app can receive next fields by form data
    - username: Your username or email
    - password: Your password

    ### Returns
    - access token and token type
    """
    access_token = auth_service.generate_token(form_data.username, form_data.password)
    return Token(access_token=access_token, token_type="bearer")
```
