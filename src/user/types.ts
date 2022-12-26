export interface JwtPayloadSub {
  id: number;
  username: string;
  email: string;
}

export interface RegisterDTO {
  username: string;
  email: string;
  password: string;
}