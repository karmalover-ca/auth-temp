import mysql from "mysql2/promise"
import { AuthToken, Room, User } from "./auth/auth_middleware";
import { LOGGER } from "./constants";

const pool = mysql.createPool({
    host: "klns.ca",
    user: "hackslc",
    password: "ThisIsAReallyStrongPasswordISwear123",
    database: "hackslc"
});

export async function query<T = any>(sql: string, values: any[]): Promise<T[]> {
    const [rows] = await pool.execute(sql, values);
    return rows as T[];
}

export const getUserByName = async (username: string): Promise<User | null> => {
    const user = await query("SELECT * FROM users WHERE username = ?;", [username])
        .then(rows => rows[0]);

    if(!user) return null;

    return {
        username: user.username,
        name: user.name,
        password_hash: user.userpass,
        scopes: JSON.parse(user.scopes) || null
    };
}

export const getUserByToken = async (token: AuthToken): Promise<User | null> => {
    const user = await getUserByName(token.user);

    if(!user) return null;

    return user;
}

export const addUser = async (user: User): Promise<boolean> => {
    console.log("test")
    await query("INSERT INTO users (username, name, userpass, scopes) VALUES (?, ?, ?, ?);", [
        user.username,
        user.name || "",
        user.password_hash,
        JSON.stringify(user.scopes)
    ]).catch(LOGGER.error);

    return true;
}

export const deleteUser = async (user: User): Promise<boolean> => {
    await query("DELETE FROM users WHERE username = ?;", [user.username]);

    return true;
}

export const addAccessToken = async (token: AuthToken): Promise<boolean> => {

    if((await getAccessToken(token.access_token)) != null) return false;

    await query("INSERT INTO accessTokens (token, createdAt, username) VALUES (?, ?, ?);", [
        token.access_token,
        token.created_at,
        token.user
    ]).catch(LOGGER.error);

    return true;
}

export const getAccessToken = async (token: string): Promise<AuthToken | null> => {
    console.log("token " + token)
    const accessToken = await query("SELECT * FROM accessTokens WHERE token = ?;", [token])
        .then(rows => rows[0]);

    if(!accessToken) return null;

    return {
        access_token: accessToken.token,
        created_at: accessToken.created_at,
        user: accessToken.username
    };
}

export const purgeAccessTokens = async (user: User): Promise<boolean> => {
    await query("DELETE FROM accessTokens WHERE username = ?;", [user.username]);

    return true;
}

export const removeAccessToken = async (token: AuthToken): Promise<boolean> => {
    await query("DELETE FROM accessTokens WHERE token = ?;", [token.access_token]);

    return true;
}

export const getRoom = async (roomNum: number): Promise<Room | null> => {
    const room = await query("SELECT * FROM rooms WHERE roomNumber = ?;", [roomNum])
        .then(rows => rows[0]);

    return room;
}

export const getRooms = async (): Promise<Room[]> => {
    const room = await query("SELECT * FROM rooms;", [null]);

    return room
}