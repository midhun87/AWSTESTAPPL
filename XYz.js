// backend.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');

// --- AWS Configuration ---
AWS.config.update({
    region: 'ap-south-1', // IMPORTANT: This region must match where your DynamoDB tables are located.
    accessKeyId: 'AKIAVEP3EDM5K3LA5J47', // Replace with your actual Access Key ID (securely!)
    secretAccessKey: 'YfIszgolrWKUglxC6Q85HSb3V0qhDsa00yv6jcIP' // Replace with your actual Secret Access Key (securely!)
});

const dynamodb = new AWS.DynamoDB.DocumentClient();

// --- Constants ---
const SECRET_KEY = 'jwt_secret_key_54742384238423_ahfgrdtTFHHYJNMP[]yigfgfjdfjd=-+&+pqiel;,,dkvntegdv/cv,mbkzmbzbhsbha#&$^&(#_enD';
const PORT = 5000;
const USER_TABLE_NAME = 'Usertable'; // Your existing user table
const TEST_ATTEMPTS_TABLE_NAME = 'TestAttempts'; // New table for test results


const NUMBER_OF_QUESTIONS_PER_TEST = 25; // Define the number of questions per test

// --- Express App Setup ---
const app = express();
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000'] // Added 127.0.0.1 for local testing
}));
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (HTML pages)
app.use(express.static(path.join(__dirname)));
app.get('/Login', (req, res) => res.sendFile(path.join(__dirname, 'Login.html')));
app.get('/Signup', (req, res) => res.sendFile(path.join(__dirname, 'Signup.html')));
app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'Home.html'))); // Corrected to Home.html
app.get('/test', (req, res) => res.sendFile(path.join(__dirname, 'Test.html'))); // New Test.html route
app.get('/certificate', (req, res) => res.sendFile(path.join(__dirname, 'Certificate.html'))); // New Certificate.html route
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'Login.html'))); // Default route

// --- Helper Function for DynamoDB Checks ---
async function checkIfAttributeExists(tableName, indexName, attributeName, value) {
    const params = {
        TableName: tableName,
        IndexName: indexName,
        KeyConditionExpression: `${attributeName} = :value`,
        ExpressionAttributeValues: { ':value': value }
    };
    try {
        const result = await dynamodb.query(params).promise();
        return result.Items && result.Items.length > 0;
    } catch (error) {
        console.error(`Error checking if attribute exists in ${tableName} (${indexName}):`, error);
        throw error; // Re-throw to be caught by calling function
    }
}

// --- User Authentication Middleware ---
function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token provided or malformed.' });
    }
    const token = authHeader.replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS512'] });
        req.user = decoded; // Contains { userId, username }
        next();
    } catch (error) {
        console.error('SERVER ERROR: JWT Verification FAILED:', error.message);
        return res.status(401).json({ message: error.name === 'TokenExpiredError' ? 'Token expired. Please log in again.' : 'Invalid token.' });
    }
}

// --- Signup Route ---
app.post('/signup', async (req, res) => {
    const { email, password, username, mobile } = req.body;

    if (!email || !password || !username || !mobile) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        if (await checkIfAttributeExists(USER_TABLE_NAME, 'Username-index', 'Username', username.toLowerCase())) {
            return res.status(400).json({ message: 'Username already in use.' });
        }
        if (await checkIfAttributeExists(USER_TABLE_NAME, 'Email-index', 'Email', email)) {
            return res.status(400).json({ message: 'Email already in use.' });
        }
        if (await checkIfAttributeExists(USER_TABLE_NAME, 'Mobile-index', 'Mobile', mobile)) {
            return res.status(400).json({ message: 'Mobile number already in use.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            UserId: uuidv4(),
            Email: email,
            Mobile: mobile,
            password: hashedPassword, // Storing hashed password
            Username: username.toLowerCase(),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        await dynamodb.put({
            TableName: USER_TABLE_NAME,
            Item: newUser
        }).promise();

        res.status(201).json({ message: 'User created successfully. Please log in.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup: ' + error.message });
    }
});

// --- Login Route ---
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const result = await dynamodb.query({
            TableName: USER_TABLE_NAME,
            IndexName: 'Email-index', // Ensure this GSI exists in DynamoDB
            KeyConditionExpression: 'Email = :email',
            ExpressionAttributeValues: { ':email': email }
        }).promise();

        const user = result.Items[0];
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials: User not found.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid credentials: Password mismatch.' });
        }

        const token = jwt.sign({ userId: user.UserId, username: user.Username, email: user.Email }, SECRET_KEY, { expiresIn: '1h', algorithm: 'HS512' });
        res.status(200).json({ token, username: user.Username, userId: user.UserId, email: user.Email, mobile: user.Mobile });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login: ' + error.message });
    }
});

// --- Validate Token Route (for client-side verification/auto-login) ---
app.get('/validate-token', authenticateUser, (req, res) => {
    // If authenticateUser middleware passes, the token is valid
    res.status(200).json({ message: 'Token is valid', user: req.user });
});

// --- Start Test Route ---
app.get('/start-test', authenticateUser, (req, res) => {
    try {
        const shuffledQuestions = [...ALL_QUESTIONS_DATA].sort(() => 0.5 - Math.random());
        const selectedQuestions = shuffledQuestions.slice(0, NUMBER_OF_QUESTIONS_PER_TEST);
        res.status(200).json({ questions: selectedQuestions });
    } catch (error) {
        console.error('Error selecting questions:', error);
        res.status(500).json({ message: 'Failed to retrieve test questions.' });
    }
});

// --- Save Test Result Route ---
app.post('/save-test-result', authenticateUser, async (req, res) => {
    const { score, totalQuestions, isPass } = req.body;
    const { userId, username } = req.user; // Get user info from authenticated token

    if (score === undefined || totalQuestions === undefined || isPass === undefined) {
        return res.status(400).json({ message: 'Missing test result data.' });
    }

    try {
        const newAttempt = {
            TestAttemptId : uuidv4(), // Corrected key name to match DynamoDB table's primary key
            UserId: userId,
            Username: username, // Store username for easier querying/display
            Score: score,
            TotalQuestions: totalQuestions,
            IsPass: isPass,
            AttemptDate: new Date().toISOString()
        };

        await dynamodb.put({
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            Item: newAttempt
        }).promise();

        res.status(201).json({ message: 'Test result saved successfully.' });
    } catch (error) {
        console.error('Error saving test result:', error);
        res.status(500).json({ message: 'Failed to save test result: ' + error.message });
    }
});

// --- Get Test History Route ---
app.get('/get-test-history', authenticateUser, async (req, res) => {
    const { userId } = req.user;

    try {
        const params = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index', // Recommended GSI for querying by UserId and sorting by AttemptDate
            KeyConditionExpression: 'UserId = :userId',
            ExpressionAttributeValues: { ':userId': userId },
            ScanIndexForward: false // To get most recent attempts first
        };
        const result = await dynamodb.query(params).promise();
        res.status(200).json({ history: result.Items || [] });
    } catch (error) {
        console.error('Error fetching test history:', error);
        res.status(500).json({ message: 'Failed to fetch test history: ' + error.message });
    }
});

app.get('/get-certificate-data', authenticateUser, async (req, res) => {
    const { userId, username, email } = req.user; // Get user info from authenticated token

    try {
        // 1. Get user details (though username and email are already in token, fetching for completeness/future expansion)
        const userParams = {
            TableName: USER_TABLE_NAME,
            Key: {
                UserId: userId // Assuming UserId is the primary key
            }
        };
        const userResult = await dynamodb.get(userParams).promise();
        const user = userResult.Item;

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // 2. Get the latest passing test attempt for this user
        const testAttemptParams = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index', // Ensure this GSI exists and is configured for UserId and AttemptDate
            KeyConditionExpression: 'UserId = :userId',
            FilterExpression: 'IsPass = :isPass', // Filter for passing attempts
            ExpressionAttributeValues: {
                ':userId': userId,
                ':isPass': true
            },
            ScanIndexForward: false, // Get the most recent attempt first
            Limit: 1 // We only need the latest one
        };

        const testAttemptResult = await dynamodb.query(testAttemptParams).promise();
        const latestPassingAttempt = testAttemptResult.Items && testAttemptResult.Items[0];

        if (!latestPassingAttempt) {
            // It's possible the user hasn't passed any test yet
            return res.status(404).json({ message: 'No passing test result found for this user.', user: { username: user.Username, email: user.Email } });
        }

        res.status(200).json({
            studentName: user.Username,
            studentEmail: user.Email,
            studentScore: latestPassingAttempt.Score,
            totalQuestions: latestPassingAttempt.TotalQuestions,
            testDate: latestPassingAttempt.AttemptDate
        });

    } catch (error) {
        console.error('Error fetching certificate data:', error);
        res.status(500).json({ message: 'Failed to fetch certificate data: ' + error.message });
    }
});



// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access frontend at http://localhost:${PORT}`);
});
