import mysql from "mysql2/promise"
import { AuthToken, User } from "./auth/auth_middleware";
import { LOGGER } from "./constants";

const pool = mysql.createPool({
    host: "klns.ca",
    user: "hackslc",
    password: "ThisIsAReallyStrongPasswordISwear123",
    database: "hackslc"
});

export async function query<T = any>(sql: string, values?: any[]): Promise<T[]> {
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
    await query("INSERT INTO users (username, name, userpass, scopes) VALUES (?, ?, ?, ?);", [
        user.username,
        user.name,
        user.password_hash,
        JSON.stringify(user.scopes) || null
    ]).catch(LOGGER.error);

    return true;
}

export const deleteUser = async (user: User): Promise<boolean> => {
    await query("DELETE FROM users WHERE username = ?;", [user.username]);

    return true;
}

export const addAccessToken = async (token: AuthToken): Promise<boolean> => {
    await query("INSERT INTO accessTokens (token, createdAt, username) VALUES (?, ?, ?);", [
        token.access_token,
        token.created_at,
        token.user
    ]).catch(LOGGER.error);

    return true;
}

export const getAccessToken = async (token: string): Promise<AuthToken | null> => {
    const accessToken = await query("SELECT * FROM accessTokens WHERE token = ?;", [token])
        .then(rows => rows[0]);

    if(!accessToken) return null;

    return {
        access_token: accessToken.token,
        created_at: accessToken.created_at,
        user: accessToken.Username
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