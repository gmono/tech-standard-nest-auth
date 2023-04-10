export interface JwtPayload {
  id: number;
}

export interface UserRegisterDto {
  username: string;
  email: string;
  password;
}
