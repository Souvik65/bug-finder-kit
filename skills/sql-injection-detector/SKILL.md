---
name: sql-injection-detector
description: >
  SQL injection vulnerability detector for multi-database, multi-language codebases.
  Detects classic SQLi, blind SQLi, second-order SQLi, NoSQL injection, and ORM
  misuse across Python, JavaScript/TypeScript, Java, PHP, Go, and Ruby applications.
  Activate when the user asks to "find SQL injection", "check for SQLi", "database
  security", "parameterized queries", "unsanitized queries", or "NoSQL injection".
triggers:
  - "find SQL injection"
  - "check for SQLi"
  - "database security"
  - "parameterized queries"
  - "unsanitized queries"
  - "NoSQL injection"
  - "injection in database"
  - "SQL vulnerability"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# SQL Injection Detector — Multi-Language, Multi-Database SQLi Scanner

> Identifies all forms of SQL injection across relational and NoSQL databases,
> ORMs, stored procedures, and dynamic query builders. Every finding includes
> the attack vector, example payload, and parameterized remediation.

---

## CWE Coverage

- **CWE-89**: SQL Injection
- **CWE-943**: NoSQL Injection
- **CWE-564**: SQL Injection via Hibernate
- **CWE-20**: Improper Input Validation (enabling SQLi)

---

## Phase 1 — Language & Database Detection

```bash
# Identify database drivers and query libraries
grep -rn "mysql\|postgresql\|sqlite\|mssql\|oracle\|mongodb\|mongoose\|sequelize\|prisma\|knex\|typeorm\|sqlalchemy\|django.db\|ActiveRecord" \
    package.json requirements.txt go.mod pom.xml Gemfile pyproject.toml 2>/dev/null | head -30

# Detect connection patterns in code
grep -rn "createConnection\|connect(\|Pool(\|engine =\|Client(\|MongoClient" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" . | head -20
```

Build a map:
| Database | Driver/ORM | Language | Files |
|---|---|---|---|

---

## Phase 2 — Classic SQL Injection Detection

### Pattern: String Concatenation in Queries

This is the most common and dangerous SQLi pattern. Any user-controlled value
concatenated directly into an SQL string is vulnerable.

### Python

```python
# VULNERABLE — flag these
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

db.query("DELETE FROM posts WHERE id=" + str(post_id))

# SQLAlchemy — raw text with user input
session.execute(text("SELECT * FROM users WHERE id=" + user_id))
session.execute("SELECT * FROM users WHERE name='" + name + "'")

# Django ORM — raw() with user input
User.objects.raw("SELECT * FROM users WHERE id=" + user_id)
User.objects.raw(f"SELECT * FROM users WHERE id={id}")
```

**SAFE patterns (do not flag):**
```python
# Parameterized queries ✓
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# Django ORM — safe ✓
User.objects.filter(id=user_id)
User.objects.get(email=email)
```

**Scan command:**
```bash
grep -rn "execute\s*(\s*[\"'].*\(%s\)\s*%\|execute\s*(\s*f[\"'].*{" --include="*.py" .
grep -rn "execute\s*(\s*[\"'].*\+\s*" --include="*.py" .
grep -rn "\.raw\s*(\s*f[\"']\|\.raw\s*(\s*[\"'].*+" --include="*.py" .
```

### JavaScript / TypeScript

```javascript
// VULNERABLE — flag these
db.query("SELECT * FROM users WHERE id=" + req.params.id)
db.query("SELECT * FROM users WHERE email='" + email + "'")
db.query(`SELECT * FROM users WHERE name='${name}'`)

// mysql2 / mysql
connection.query("SELECT * FROM orders WHERE user_id=" + userId)

// pg (node-postgres)
client.query("SELECT * FROM items WHERE name='" + item + "'")

// Knex — raw with interpolation
knex.raw("SELECT * FROM users WHERE id=" + id)
knex.raw(`SELECT * FROM users WHERE name='${name}'`)

// TypeORM — raw query
repository.query("SELECT * FROM users WHERE id=" + id)
getManager().query(`DELETE FROM sessions WHERE user='${user}'`)
```

**SAFE patterns:**
```javascript
// Parameterized ✓
db.query("SELECT * FROM users WHERE id = ?", [req.params.id])
client.query("SELECT * FROM users WHERE id = $1", [userId])
knex("users").where("id", userId)  // ORM builder ✓
knex.raw("SELECT * FROM users WHERE id = ?", [id])  // binding ✓
```

**Scan command:**
```bash
grep -rn "\.query\s*(\s*[\"'].*+\|\.query\s*(\s*\`.*\$" --include="*.js" --include="*.ts" .
grep -rn "knex\.raw\s*(\s*[\"'].*+\|knex\.raw\s*(\s*\`.*\$" --include="*.js" --include="*.ts" .
grep -rn "repository\.query\s*(\s*[\"'].*+\|getManager.*query.*\`" --include="*.ts" .
```

### PHP

```php
// VULNERABLE — flag these
mysql_query("SELECT * FROM users WHERE id=" . $_GET['id']);
mysqli_query($conn, "SELECT * FROM users WHERE name='" . $_POST['name'] . "'");
$pdo->query("SELECT * FROM users WHERE email='" . $email . "'");

// Prepared statement constructed incorrectly
$stmt = $pdo->prepare("SELECT * FROM " . $tableName . " WHERE id=?"); // table injection
```

**SAFE patterns:**
```php
// PDO prepared statements ✓
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// MySQLi prepared statements ✓
$stmt = $mysqli->prepare("SELECT * FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
```

**Scan command:**
```bash
grep -rn "mysql_query\s*(\|mysqli_query\s*([^,]\+,[^,]*\.\s*\$" --include="*.php" .
grep -rn "\$pdo->query\s*(\s*[\"'].*\.\s*\$" --include="*.php" .
```

### Go

```go
// VULNERABLE — flag these
db.Query("SELECT * FROM users WHERE id=" + id)
db.Query(fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name))
db.Exec("DELETE FROM sessions WHERE user='" + user + "'")

// GORM raw
db.Raw("SELECT * FROM users WHERE id=" + id).Scan(&users)
db.Exec("UPDATE users SET role='" + role + "' WHERE id=" + id)
```

**SAFE patterns:**
```go
// Parameterized ✓
db.Query("SELECT * FROM users WHERE id = $1", id)
db.Query("SELECT * FROM users WHERE name = ?", name)
// GORM safe ✓
db.Where("id = ?", id).Find(&users)
db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&users)
```

**Scan command:**
```bash
grep -rn "db\.Query\s*(.*Sprintf\|db\.Exec\s*(.*+\|db\.Raw\s*(.*+" --include="*.go" .
```

### Java

```java
// VULNERABLE — flag these
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
stmt.executeUpdate("DELETE FROM sessions WHERE user='" + username + "'");

// JDBC with string formatting
String query = "SELECT * FROM users WHERE name='" + name + "'";
conn.prepareStatement(query).executeQuery();  // still vuln if query contains concat

// JPA native query
em.createNativeQuery("SELECT * FROM users WHERE id=" + id);
entityManager.createQuery("FROM User WHERE id=" + id);  // HQL injection
```

**SAFE patterns:**
```java
// PreparedStatement ✓
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, id);
ResultSet rs = stmt.executeQuery();

// JPA parameterized ✓
em.createNativeQuery("SELECT * FROM users WHERE id = :id")
  .setParameter("id", id);
```

---

## Phase 3 — Second-Order SQL Injection

Second-order SQLi occurs when user input is stored safely but later used unsafely in another query.

```python
# Step 1 — input safely stored (won't trigger on first scan)
cursor.execute("INSERT INTO users (username) VALUES (%s)", (username,))

# Step 2 — stored value used unsafely later (may be in different file/function)
cursor.execute("SELECT * FROM logs WHERE username='" + row['username'] + "'")
#                                                    ^^^ was stored from user input!
```

**Detection approach:**
1. Find all places where user input is written to the database (INSERT, UPDATE).
2. Find all places where database values are used in subsequent queries without parameterization.
3. Cross-reference: if a column written by user maps to a column read in query #2, flag it.

---

## Phase 4 — ORM Misuse

### Django ORM
```python
# VULNERABLE — bypass ORM's protections
User.objects.raw("SELECT * FROM auth_user WHERE username='" + username + "'")
User.objects.extra(where=["id=" + str(user_id)])  # deprecated but still dangerous

# Safe — Django ORM with lookups ✓
User.objects.filter(username=username)
User.objects.get(id=user_id)
```

### Sequelize (Node.js)
```javascript
// VULNERABLE — literal injection
User.findAll({ where: sequelize.literal("id=" + req.params.id) })
User.findAll({ where: { [Op.and]: sequelize.literal("name='" + name + "'") } })

// Safe ✓
User.findAll({ where: { id: req.params.id } })
User.findAll({ where: { name: name } })
```

### ActiveRecord (Rails)
```ruby
# VULNERABLE — interpolation in where
User.where("name = '#{params[:name]}'")
User.where("id = " + params[:id])
Order.find_by("status = '#{status}'")

# Safe ✓
User.where(name: params[:name])
User.where("name = ?", params[:name])
User.where("id = ?", params[:id])
```

```bash
grep -rn '\.where\s*(\s*".*#{' --include="*.rb" .
grep -rn '\.where\s*(\s*".*\+\s*' --include="*.rb" .
```

---

## Phase 5 — NoSQL Injection

### MongoDB (JavaScript/Node.js)

```javascript
// VULNERABLE — user-controlled operator injection
db.collection("users").findOne({ username: req.body.username, password: req.body.password })
// Attacker sends: { "username": "admin", "password": { "$gt": "" } }
// The $gt operator bypasses password check!

// Also vulnerable:
db.collection("users").findOne(JSON.parse(req.body.query))  // arbitrary query injection

// $where injection — JavaScript execution
db.collection("users").find({ $where: "this.credit > " + userInput })
```

**Safe patterns:**
```javascript
// Validate types before using in query ✓
const username = String(req.body.username)
const password = String(req.body.password)
db.collection("users").findOne({ username, password })

// Use schema validation / mongoose ✓
const schema = new mongoose.Schema({ username: { type: String, required: true } })
```

**Scan command:**
```bash
grep -rn "findOne\s*({.*req\.\|find\s*({.*req\.\|find\s*({.*params\." --include="*.js" --include="*.ts" .
grep -rn "\\\$where.*user\|where.*req\.\|JSON\.parse.*body" --include="*.js" --include="*.ts" .
```

### Python / PyMongo
```python
# VULNERABLE
users.find_one({"username": request.json.get("username"), "password": request.json.get("password")})
# Attacker sends: {"password": {"$gt": ""}} — bypasses check

# Safe — validate type
username = str(request.json.get("username"))
password = str(request.json.get("password"))
```

---

## Phase 6 — Stored Procedure Analysis

```sql
-- VULNERABLE — dynamic SQL in stored procedure
CREATE PROCEDURE GetUser @username VARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(500)
    SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
    EXEC(@sql)  -- dynamic SQL with concat = SQLi
END

-- SAFE — parameterized stored procedure
CREATE PROCEDURE GetUser @username VARCHAR(100)
AS
BEGIN
    SELECT * FROM users WHERE username = @username  -- direct param use ✓
END
```

```bash
grep -rn "EXEC\s*(@sql\|sp_executesql.*+" --include="*.sql" .
grep -rn "EXECUTE\s*(.*CONCAT\|EXECUTE\s*(.*\+" --include="*.sql" .
```

---

## Output Format

````markdown
## [SEVERITY] SQLI-[NNN]: [SQLi Type] in [Function/Endpoint]

**Type:** Classic | Blind | Second-order | NoSQL | ORM misuse
**CWE:** CWE-89 / CWE-943
**Database:** MySQL | PostgreSQL | SQLite | MongoDB | Oracle | MSSQL
**Language:** [Language/Framework]

### Location
- **File:** `path/to/file.ext:LINE`
- **Function/Route:** `getUserById()` / `GET /users/:id`

### Vulnerable Code
```[lang]
[exact vulnerable code snippet]
```

### Attack Vector
Attacker-controlled input: `req.params.id`
Example payload: `1 OR 1=1 --` (for authentication bypass)
Full malicious request: `GET /users/1%20OR%201%3D1%20--`

### Impact
[Data exfiltration / Authentication bypass / Data deletion / RCE via xp_cmdshell]

### Remediation
```[lang]
[safe replacement using parameterized query]
```

### References
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection
````

---

## Severity Matrix

| Scenario | Severity |
|---|---|
| Unauthenticated SQLi with error-based data extraction | CRITICAL |
| SQLi via login form enabling auth bypass | CRITICAL |
| Authenticated SQLi with full table access | HIGH |
| Blind SQLi (boolean/time-based) | HIGH |
| Second-order SQLi | HIGH |
| NoSQL injection bypassing authentication | CRITICAL |
| ORM raw query with partial user control | MEDIUM |
| Stored procedure dynamic SQL with validation | MEDIUM |

---

## Rules of Engagement

1. **Check both ORM and raw queries** — ORMs don't eliminate SQLi if `.raw()` is misused.
2. **Trace data flow** — follow user input from HTTP request to database call.
3. **Second-order requires two-pass scan** — check writes and reads separately.
4. **NoSQL ≠ safe** — MongoDB and other NoSQL databases have operator injection risks.
5. **Include database type** — remediation syntax differs between MySQL, PostgreSQL, SQLite.
6. **Parameterization is the fix** — input validation is not sufficient on its own.
