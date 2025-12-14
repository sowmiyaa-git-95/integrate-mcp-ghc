from pydantic import BaseModel, EmailStr


class SignupModel(BaseModel):
    email: EmailStr


class UnregisterModel(BaseModel):
    email: EmailStr


class AdminCreate(BaseModel):
    username: str
    password: str


class AdminLogin(BaseModel):
    username: str
    password: str
