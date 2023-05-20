const https = require("https");
const Express = require("express");
const { Password, cacher, useJwt } = require("./utils");
const Database = require("better-sqlite3");
const fs = require("node:fs");

if (!process.env.JWT_SECRET) throw new Error("Missing Environment Variable JWT_SECRET");

const app = Express();

const db = new Database("paradox.sqlite3", { verbose: console.log }).exec(
    fs.readFileSync("migration.sql", { encoding: "utf-8" })
);

app.use(Express.json());

app.post("/register", async (req, res) => {
    const { username = "", password = "", avatar = "" } = req.body;

    try {
        const user = db
            .prepare(
                "INSERT INTO users (username, password, avatar) VALUES (?, ?, ?) RETURNING username, avatar, level"
            )
            .get(username, await Password.hash(password), avatar);
        res.json(user);
    } catch (err) {
        if (err.code === "SQLITE_CONSTRAINT_CHECK")
            return res.status(400).json({ error: "Username must be between 3 and 20 characters" });

        if (err instanceof Password.PasswordLengthError)
            return res.status(400).json({ error: "Password must be between 8 and 100 characters" });

        if (err.code === "SQLITE_CONSTRAINT")
            return res.status(400).json({ error: "Username already taken" });

        res.status(500).json({ error: "Internal server error" });
        console.err(err);
    }
});

const [login, authorize] = useJwt(process.env.JWT_SECRET, "HS256", "2d");

app.post("/login", async (req, res) => {
    const { username = "", password = "" } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user || !(await Password.verify({ hashed: user.password, password })))
        return res.status(401).json({ error: "Invalid username or password" });

    const token = login({ username });
    res.json({ token });
});

app.get("/me", authorize, (req, res) => {
    res.json(db.prepare("SELECT username, level FROM users WHERE username = ?").get(req.username));
});

app.get("/question", authorize, (req, res) => {
    res.json(
        db
            .prepare(
                "SELECT level, text, image FROM questions WHERE level = (SELECT level FROM users WHERE username = ?)"
            )
            .get(req.username)
    );
});

app.post("/answer", authorize, (req, res) => {
    const { answer = "" } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(req.username);
    const question = db.prepare("SELECT * FROM questions WHERE level = ?").get(user.level);

    if (!question) return res.json({ error: "No more questions" });

    db.prepare("INSERT INTO attempts (username, level, attempt) VALUES (?, ?, ?)").run(
        user.username,
        user.level,
        answer
    );

    if (answer !== question.answer) return res.json({ correct: false });

    db.prepare(
        "UPDATE users SET level = level + 1, reachedAt = CURRENT_TIMESTAMP WHERE username = ?"
    ).run(user.username);

    res.json({ correct: true });
});

const leaderboardStmt = db.prepare(
    "SELECT username, avatar, level FROM users ORDER BY level DESC, reachedAt ASC"
);
const leaderboard = cacher(60)(() => leaderboardStmt.all());
app.get("/leaderboard", (_, res) => res.json(leaderboard()));

if (process.env.NODE_ENV !== "production")
    app.listen(3000, () => console.log("Listening on port 3000"));
else {
    if (!process.env.KEY || !process.env.CERT) {
        throw new Error("Missing environment variables KEY and/or CERT");
    }

    const server = https.createServer(
        {
            key: fs.readFileSync(process.env.KEY),
            cert: fs.readFileSync(process.env.CERT),
        },
        app
    );

    server.listen(443, () => console.log("Listening on port 443"));
}
