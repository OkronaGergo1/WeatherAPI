var cors = require('cors');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
var sha1 = require('sha1');

const app = express();
const port = process.env.APP_PORT;

const pswdRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/;

var pool = mysql.createPool({
    connectionLimit:     process.env.DB_CONN_LIMIT,
    multipleStatements:  process.env.DB_MULTI_QUERY,
    host:                process.env.DB_HOST,
    user:                process.env.DB_USER,
    password:            process.env.DB_PASS,
    port:                process.env.DB_PORT,
    database:            process.env.DB_NAME,
    timezone:            process.env.DB_TIMEZONE,
})

app.use(cors());
app.use(express.urlencoded({ extended: true}));
app.use(express.json());

app.get('/', (_req, res) =>{
    res.send('Welcome to the Weather API!');
});

//USERS --------------------------------

// registration
app.post('/users/register', (req, res) => {

    const { name, email, passwd, confirm } = req.body;

    if (!name || !email || !passwd || !confirm) {
        return res.status(400).json({error: 'Missing required fields'});
    }

    if (passwd !== confirm) {
        return res.status(400).json({error: 'Passwords do not match'});
    }

    if (!passwd.match(pswdRegex)) {
        return res.status(400).json({error: 'The new password is too weak!'});
    }

    pool.query('SELECT id FROM users WHERE email = ?', [email], (error, results) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length > 0) {
            return res.status(400).json({error: 'This e-mail already exists'});
        }

    pool.query(`INSERT INTO users (name, email, passwd, role, status) VALUES (?, ?, SHA1(?), 'user', 'active')`, [name, email, passwd], (error, results) => {
        if (error) {
            return res.status(500).json({error: 'Database insert error'});
        }
        res.status(201).json({message: 'User registered successfully'});
        });
    });
});
// login
app.post('/users/login', (req, res) => {

    const { email, passwd } = req.body;

    if (!email || !passwd) {
        return res.status(400).json({error: 'Missing required fields'});
    }

    pool.query('SELECT * FROM users WHERE email=? AND passwd=SHA1(?)', [email, passwd], (error, results) => {
        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0) {
            return res.status(400).json({error: 'Invalid credentials!'});
        }
        if (results[0].status === 'blocked') {
            return res.status(400).json({error: 'This user is blocked by admin!'});
        }
        const loggedUser = {
            id: results[0].id,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        };
    pool.query('UPDATE users SET last=CURRENT_TIMESTAMP, loginCount=loginCount+1 WHERE id=?', [loggedUser.id], (error, results) => {
        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        return res.status(200).json({message: 'You are successfully logged in!', loggedUser});
        });
    });
});
// get profile
app.get('/users/:uid', (req, res) => {
    const uid = req.params.uid;

    if (!uid) {
        return res.status(400).json({error: 'Missing user identifier'});
    }

    pool.query('SELECT * FROM users WHERE id = ?',[uid],(error, results) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length === 0) {
            return res.status(400).json({error: 'User with this ID does not exist!'});
        }
        const user = {
            id: results[0].id,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role,
            status: results[0].status,
            reg: results[0].reg,
            last: results[0].last,
            loginCount: results[0].loginCount
        };
        return res.status(200).json({results: user});
    });
});
// update profile
app.patch('/users/:uid', (req, res) => {

    const uid = req.params.uid;
    const { username, email, luid } = req.body;

    if (!uid || !username || !email || !luid) {
        return res.status(400).json({error: 'Missing required fields'});
    }

    if (uid != luid) {
        return res.status(400).json({error: 'You don\'t have permission to update this user!'});
    }

    pool.query('SELECT * FROM users WHERE id=?',[uid],(error, results) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length === 0) {
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }
        if (username === results[0].name && email === results[0].email) {
            return res.status(200).json({message: 'No update occured!'});
        }

    pool.query('SELECT * FROM users WHERE email=? AND id<>?',[email, uid],(error, results2) => {
        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results2.length > 0) {
            return res.status(400).json({error: 'This e-mail address is already used!'});
        }
        pool.query('UPDATE users SET name=?, email=? WHERE id=?',[username, email, uid],(error, results3) => {
            if (error) {
                return res.status(500).json({error: 'Database query error'});
            }
            return res.status(200).json({message: 'User updated successfully!'});
            });
        });
    });
});
// password change
app.post('/users/:uid/passmod', (req, res) => {

    const { oldpass, newpass, confirm } = req.body;
    const uid = req.params.uid;

    if (!oldpass || !newpass || !confirm) {
        return res.status(400).json({error: 'Missing required fields'});
    }

    if (newpass != confirm) {
        return res.status(400).json({error: 'The new password and its confirm doesn\'t match!'});
    }

    if (oldpass == newpass) {
        return res.status(400).json({error: 'The new password equals with old password!'});
    }

    if (!newpass.match(pswdRegex)) {
        return res.status(400).json({error: 'The new password is too weak!'});
    }

    pool.query('SELECT passwd FROM users WHERE id=?', [uid], (error, results) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0) {
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }
        const oldpassHash = sha1(oldpass);
        if (results[0].passwd != oldpassHash) {
            return res.status(400).json({error: 'The old password is not correct!'});
        }
    pool.query('UPDATE users SET passwd=? WHERE id=?', [sha1(newpass), uid],(error, results2) => {
        if (error) {
            return res.status(500).json({
                error: 'Database query error'
            });
        }
        return res.status(200).json({
            message: 'The password successfully modified!'
            });
        });
    });
});
// delete profile
app.delete('/users/:uid', (req, res) =>{
    const uid = req.params.uid;
    const loggedUserID = req.body.luid;

    if (!uid || !loggedUserID) {
        return res.status(400).json({ error: 'Missing user identifier' });
    }

    if (uid != loggedUserID) {
        return res.status(400).json({ error: 'You don\'t have permission to delete this user!' });
    }

    pool.query('DELETE FROM users WHERE id=?', [uid], (error, results) =>{
        if (error){
            return res.status(500).json({ error: 'Database query error' });
        }
        if (results.affectedRows == 1) {
            return res.status(200).json({ message: 'User deleted successfully!' });
        }

        return res.status(200).json({ message: 'No deletion occured!' });

    })
})

//WEATHER --------------------------------

//creat weather
app.post('/weather', (req, res) => {

    const {
        luid,
        date,
        location,
        temp_min,
        temp_max,
        weather_type,
        precipitation,
        precipitation_probability,
        wind_speed,
        wind_direction,
        humidity,
        pressure,
        uv_index
    } = req.body;

    if (!luid || !date || !location || temp_min == null || temp_max == null || !weather_type) {
        return res.status(400).json({error: 'Missing required fields!' });
    }
    pool.query('SELECT * FROM users WHERE id=?', [luid], (error, results1) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }

        if (results1.length == 0) {
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }

        if (results1[0].role != 'admin') {
            return res.status(403).json({error: 'You don\'t have permission to create forecast!'});
        }

    pool.query(
        `INSERT INTO weather_forecasts
        (
            date,
            location,
            temp_min,
            temp_max,
            weather_type,
            precipitation,
            precipitation_probability,
            wind_speed,
            wind_direction,
            humidity,
            pressure,
            uv_index
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            date,
            location,
            temp_min,
            temp_max,
            weather_type,
            precipitation,
            precipitation_probability,
            wind_speed,
            wind_direction,
            humidity,
            pressure,
            uv_index
        ],
        (error, results2) => {
            if (error) {
                return res.status(500).json({error: 'Database insert error'});
            }
            return res.status(201).json({message: 'Forecast created successfully!'});
        });
    });
});
// get all weather
app.get('/weather', (_req, res) => {

    pool.query(
        `SELECT
            id,
            location,
            temp_min,
            temp_max,
            weather_type
         FROM weather_forecasts ORDER BY date`,
        (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error'});
            }
            return res.status(200).json(results);
    });
});
// get weather details
app.get('/weather/:wid', (req, res) => {

    const wid = req.params.wid;

    if (!wid) {
        return res.status(400).json({error: 'Missing weather identifier'});
    }

    pool.query('SELECT * FROM weather_forecasts WHERE id=?', [wid], (error, results) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'Forecast doesn\'t exist!'});
        }
        return res.status(200).json(results[0]);
    });
});
//update weather
app.patch('/weather/:wid', (req, res) => {

    const wid = req.params.wid;
    const {
        luid,
        date,
        location,
        temp_min,
        temp_max,
        weather_type,
        precipitation,
        precipitation_probability,
        wind_speed,
        wind_direction,
        humidity,
        pressure,
        uv_index
    } = req.body;

    if (!wid || !luid) {
        return res.status(400).json({error: 'Missing required fields!'});
    }

    pool.query('SELECT * FROM users WHERE id=?', [luid], (error, results1) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }

        if (results1.length == 0) {
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }

        if (results1[0].role != 'admin') {
            return res.status(403).json({error: 'You don\'t have permission to update forecast!'});
        }

    pool.query(
        `UPDATE weather_forecasts SET
            date=?,
            location=?,
            temp_min=?,
            temp_max=?,
            weather_type=?,
            precipitation=?,
            precipitation_probability=?,
            wind_speed=?,
            wind_direction=?,
            humidity=?,
            pressure=?,
            uv_index=?
            WHERE id=?`,
        [
            date,
            location,
            temp_min,
            temp_max,
            weather_type,
            precipitation,
            precipitation_probability,
            wind_speed,
            wind_direction,
            humidity,
            pressure,
            uv_index,
            wid
        ],
        (error, results2) => {
            if (error) {
                return res.status(500).json({error: 'Database query error'});
            }
            return res.status(200).json({message: 'Forecast updated successfully!'});
        });
    });
});
//delete weather
app.delete('/weather/:wid', (req, res) => {

    const wid = req.params.wid;
    const luid = req.body.luid;

    if (!wid || !luid) {
        return res.status(400).json({error: 'Missing required fields!'});
    }

    pool.query('SELECT * FROM users WHERE id=?', [luid], (error, results1) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }

        if (results1.length == 0) {
            return res.status(400).json({error: 'User with this ID doesn\'t exist!'});
        }

        if (results1[0].role != 'admin') {
            return res.status(403).json({error: 'You don\'t have permission to delete forecast!'});
        }

    pool.query('DELETE FROM weather_forecasts WHERE id=?', [wid], (error, results2) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error'});
            }
            if (results2.affectedRows == 1) {
                return res.status(200).json({ message: 'Forecast deleted successfully!'});
            }
            return res.status(200).json({
                message: 'No deletion occured!'
            });
        });
    });
});

//ADMIN --------------------------------

// get all users
app.post('/admin/users', (req, res) => {
    const luid  = req.body.luid;

    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields!' });
    }   

    pool.query('SELECT * FROM users WHERE id=?', [luid], (error, results1) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' });
        }

        if (results1.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
        }

        if (results1[0].role != 'admin') {
            return res.status(403).json({ error: 'You don\'t have permission to get users list!' });
        }  

        pool.query('SELECT * FROM users', (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error' });
            }

            return res.status(200).json(results);
        });
    });
});
// deny user
app.patch('/admin/status', (req, res) => {
    const { uid, luid } = req.body;

    if (!uid || !luid) {
        return res.status(400).json({ error: 'Missing required fields!' });
    }

    pool.query('SELECT * FROM users WHERE id=?', [luid], (error, results1) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' });
        }

        if (results1.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
        }

        if (results1[0].role != 'admin') {
            return res.status(400).json({ error: 'You don\'t have permission to change this user status!' });
        }

        pool.query('SELECT * FROM users WHERE id=?', [uid], (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error' });
            }

            if (results.length == 0) {
                return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
            }

            pool.query(`UPDATE users SET status = CASE WHEN status='active' THEN 'blocked' ELSE 'active' END WHERE id=?`, [uid], (error, results2) => {
                if (error) {
                    return res.status(500).json({ error: 'Database query error' });
                }

                return res.status(200).json({ message: 'User status changed!' });
            });
        });
    });
});
// statistics   
app.post('/admin/statistics', (req, res) => {

    const luid = req.body.luid;

    if (!luid) {
        return res.status(400).json({error: 'Missing required fields!'});
    }

    pool.query('SELECT * FROM users WHERE id=?', [luid], (error, results) => {

        if (error) {
            return res.status(500).json({error: 'Database query error'});
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exist!'});
        }
        if (results[0].role != 'admin') {
            return res.status(403).json({error: 'You don\'t have permission to get statistics!'});
        }
        pool.query(`
            SELECT
                COUNT(*) AS totalUsers FROM users;
            SELECT 
                COUNT(*) AS activeUsers FROM users WHERE status='active';
            SELECT 
                COUNT(*) AS blockedUsers FROM users WHERE status='blocked';
            SELECT 
                COUNT(*) AS totalForecasts FROM weather_forecasts;
        `, (error, results2) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error'});
            }
            return res.status(200).json({
                totalUsers: results2[0][0].totalUsers,
                activeUsers: results2[1][0].activeUsers,
                blockedUsers: results2[2][0].blockedUsers,
                totalForecasts: results2[3][0].totalForecasts
            });
        });
    });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});