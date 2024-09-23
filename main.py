from datetime import datetime, timedelta
from typing import Optional, List

import jwt
from fastapi import FastAPI, Depends, HTTPException, Form, UploadFile, File, Cookie
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI()

# Настройки
SECRET_KEY = "supersecret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Модели
class User(BaseModel):
    username: str
    email: str
    full_name: str
    photo: Optional[UploadFile] = None
    hashed_password: str

class Flower(BaseModel):
    id: int
    name: str
    price: float

class Purchase(BaseModel):
    user_id: int
    flower_id: int

class UsersRepository:
    users = []

    def add_user(self, user: User):
        self.users.append(user)

    def get_user(self, username: str):
        for user in self.users:
            if user.username == username:
                return user
        return None

class FlowersRepository:
    flowers = []
    id_counter = 1

    def add_flower(self, flower: Flower):
        flower.id = self.id_counter
        self.flowers.append(flower)
        self.id_counter += 1
        return flower.id

    def get_flowers(self) -> List[Flower]:
        return self.flowers

    def get_flower(self, flower_id: int) -> Optional[Flower]:
        for flower in self.flowers:
            if flower.id == flower_id:
                return flower
        return None

class PurchasesRepository:
    purchases = []

    def add_purchase(self, user_id: int, flower_id: int):
        purchase = Purchase(user_id=user_id, flower_id=flower_id)
        self.purchases.append(purchase)

    def get_user_purchases(self, user_id: int) -> List[Purchase]:
        return [p for p in self.purchases if p.user_id == user_id]

users_repository = UsersRepository()
flowers_repository = FlowersRepository()
purchases_repository = PurchasesRepository()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Обработчики
@app.post("/signup")
async def signup(username: str = Form(...), email: str = Form(...), full_name: str = Form(...),
                 password: str = Form(...), photo: UploadFile = File(None)):
    hashed_password = get_password_hash(password)
    user = User(username=username, email=email, full_name=full_name, hashed_password=hashed_password, photo=photo)
    users_repository.add_user(user)
    return {"status": "200 OK"}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_repository.get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/profile")
async def get_profile(token: str = Depends(oauth2_scheme)):
    user_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user = users_repository.get_user(user_data["sub"])
    return user.dict(exclude={"hashed_password"})

@app.get("/flowers")
async def get_flowers():
    return flowers_repository.get_flowers()

@app.post("/flowers")
async def add_flower(name: str = Form(...), price: float = Form(...)):
    flower = Flower(id=0, name=name, price=price)
    flower_id = flowers_repository.add_flower(flower)
    return {"id": flower_id}

@app.post("/cart/items")
async def add_to_cart(flower_id: int = Form(...), cart: str = Cookie(None)):
    # Получаем текущие товары из корзины
    items = cart.split(",") if cart else []
    items.append(str(flower_id))
    # Сохраняем обновлённый список в куки
    response = {"status": "200 OK"}
    response.set_cookie(key="cart", value=",".join(items))
    return response

@app.get("/cart/items")
async def get_cart_items(cart: str = Cookie(None)):
    items = cart.split(",") if cart else []
    flowers = [flowers_repository.get_flower(int(flower_id)) for flower_id in items]
    total_price = sum(flower.price for flower in flowers)
    return {"items": flowers, "total_price": total_price}

@app.post("/purchased")
async def purchase_items(token: str = Depends(oauth2_scheme), cart: str = Cookie(None)):
    user_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = users_repository.get_user(user_data["sub"]).username 
    items = cart.split(",") if cart else []
    for flower_id in items:
        purchases_repository.add_purchase(user_id, int(flower_id))
    return {"status": "200 OK"}

@app.get("/purchased")
async def get_purchased_items(token: str = Depends(oauth2_scheme)):
    user_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = users_repository.get_user(user_data["sub"]).username
    purchases = purchases_repository.get_user_purchases(user_id)
    return {"items": purchases}
