import { DataSource } from "typeorm"

export const createDataSource = async () => {
  const AppDataSource = new DataSource({
    type: "mysql",
    host: "localhost",
    port: 3306,
    username: "test",
    password: "test",
    database: "test",
  })

  await AppDataSource.initialize();
  return AppDataSource;
}
