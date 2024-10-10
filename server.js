const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const { initializeApp } = require("firebase/app");
const { getDatabase, ref, get, update, set } = require("firebase/database");
const cors = require('cors');
const bcrypt = require('bcryptjs');


// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyDwJCLWXbvzSJXVKjIyfGuVc7T77uwAfqc",
    authDomain: "rapidaimx.firebaseapp.com",
    databaseURL: "https://rapidaimx-default-rtdb.firebaseio.com",
    projectId: "rapidaimx",
    storageBucket: "rapidaimx.appspot.com",
    messagingSenderId: "692553501769",
    appId: "1:692553501769:web:95f952e6205b6421158398"
};

// Initialize Firebase and Realtime Database
const fireapp = initializeApp(firebaseConfig);
const database = getDatabase(fireapp);

// Load environment variables from .env file
dotenv.config();

// Initialize Express App
const app = express();
// Increase the limit for incoming JSON request body
app.use(bodyParser.json({ limit: '50mb' }));  // or larger if needed
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));


// Enable CORS and allow credentials
app.use(cors({
    origin: process.env.NODE_ENV === "development"? 'http://localhost:3000' : "https://valobio.onrender.com/", // Specify the origin explicitly
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true, // Allow credentials (cookies, tokens, etc.)
}));

app.use(bodyParser.json());
// Use cookie-parser
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Helper function to sanitize email (replace dots with commas)
const sanitizeEmail = (email) => email.replace(/\./g, ',').split("@")[0];

// Register user
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        const sanitizedEmail = sanitizeEmail(email);
        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

        // Reference to user data in Realtime Database
        const userRef = ref(database, `users/${sanitizedEmail}`);

        // Check if user already exists
        const userSnapshot = await get(userRef);

        // If user doesn't exist, create new user
        if (!userSnapshot.exists()) {
            console.log("User does not exist. Creating new user...");
            await set(userRef, {
                email,
                password: hashedPassword, // Store hashed password
            });

            const token = jwt.sign({ uid: sanitizedEmail, email }, JWT_SECRET, {
                expiresIn: '1h',
            });
            // Set token in HttpOnly cookie
            res.cookie('token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 3600000 // 1 hour
            });
            return res.status(201).json({
                status: true,
                message: 'User registered successfully',
                token, // Only token is sent in the response
                user: { uid: sanitizedEmail, email } // Avoid sensitive data, send only necessary info
            });
        } else {
            return res.status(400).json({ status: false, message: 'User already exists' });
        }
    } catch (error) {
        res.status(400).json({
            status: false, message: 'Registration failed', error: error.message
        });
    }
});

// User login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const sanitizedEmail = sanitizeEmail(email);

        // Reference to user data in Realtime Database
        const userRef = ref(database, `users/${sanitizedEmail}`);
        const userSnapshot = await get(userRef);

        // Check if user exists and password matches
        if (userSnapshot.exists()) {
            const userData = userSnapshot.val();
            const passwordMatch = await bcrypt.compare(password, userData.password); // Compare hashed password

            if (passwordMatch) {
                const token = jwt.sign({ uid: sanitizedEmail, email }, JWT_SECRET, {
                    expiresIn: '1h',
                });

                // Set token in HttpOnly cookie
                res.cookie('token', token, {
                    httpOnly: true, // Prevents JavaScript access
                    secure: true,   // Ensures cookie is sent over HTTPS only
                    sameSite: 'Strict', // Helps prevent CSRF
                    maxAge: 3600000 // 1 hour
                });
                // Return the token and user information without sensitive data
                return res.json({
                    status: true,
                    message: 'Login successful',
                    token, // Only token is sent in the response
                    user: { uid: sanitizedEmail, email },
                });
            }
        }

        return res.status(401).json({ status: false, message: 'Invalid email or password' });
    } catch (error) {
        res.status(401).json({ status: false, message: 'Login failed', error: error.message });
    }
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.cookies.token; // Get token from cookies
    if (!token) {
        return res.status(403).json({ status: false, message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ status: false, message: 'Failed to authenticate token' });
        }
        req.userId = decoded.uid; // Add userId to request for further processing
        next();
    });
}

app.post('/validToken', verifyToken, async (req, res) => {
    res.json({ status: true });
});

// Store saveprofile endpoint
app.post('/saveprofile', verifyToken, async (req, res) => {
    const { userId } = req;
    const { firstName, lastName, userEmail , image} = req.body;
    try {
        // Reference to user data in Realtime Database 
        const userRef = ref(database, `users/${userId}`); 
        const data = {
            firstName: firstName,
            lastName: lastName,
            userEmail: userEmail,
            image: image
        }
        await update(userRef, {
            profile:data ,
        });

        return res.json({
            status: true,
            message: 'Data stored successfully',
            profile: data
        });
    } catch (error) {
        res.status(401).json({ status: false, message: 'Login failed', error: error.message });
    }
}); 
app.post('/savelinks', verifyToken, async (req, res) => {
    const { userId } = req;
    const { links } = req.body;
    try {
        // Reference to user data in Realtime Database 
        const userRef = ref(database, `users/${userId}`);  
        await update(userRef, {
            links:links  
        });

        return res.json({
            status: true,
            message: 'Data stored successfully',
            links: links
        });
    } catch (error) {
        res.status(401).json({ status: false, message: 'Login failed', error: error.message });
    }
}); 


async function getUser(req, res, uid) { 
    // Set header to specify the content type as JSON
    res.setHeader('Content-Type', 'application/json');

    try {
        const userRef = ref(database, `users/${uid}`);
        const snapshot = await get(userRef);

        if (snapshot.exists()) {
            // Respond with the user data in JSON format
            res.status(200).json(
                {
                    status:true,
                    uid:uid,
                    links: snapshot.child("links").val(),
                    profile: snapshot.child("profile").val()
                }
            );
        } else {
            // If no data found, respond with a 404 and a JSON message
            res.status(404).json({ status: false, message: 'No data found' });
        }
    } catch (error) {
        // On error, respond with a 500 status and error message in JSON format
        res.status(500).json({ status: false, message: 'Failed to retrieve data', error: error.message });
    }
}


// Get user data
app.post('/userbytoken', verifyToken, async (req, res) => {
    const { userId } = req;
    getUser(req, res , userId); 
}); 
app.get('/user/:uid', async (req, res) => {
    const { uid } = req.params;
    getUser(req, res, uid); 
});



// Start the server
const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
