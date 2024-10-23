    import express from 'express';
    import bodyParser from 'body-parser';
    import mongoose from 'mongoose';
    import bcrypt from 'bcrypt';
    import User from './models/userSchema.js';
    import Driver from './models/driverSchema.js';
    import { v4 as uuidv4 } from 'uuid';
    import session from 'express-session';
    import Feedback from './models/feedbackSchema.js'; 

    const app = express();

    app.use(session({
        secret: 'your_secret_key',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false } // Set true in production (HTTPS)
    }));
    app.use(express.json())
    app.use(express.static('public'));
    app.use(bodyParser.urlencoded({ extended: true }));

    (async () => {
        try {
            await mongoose.connect("mongodb://localhost:27017/todo");
            console.log("Connected to MongoDB");
        } catch (error) {
            console.error("Error connecting to MongoDB:", error);
        }
    })();

    app.set('views', './views');

    app.set('view engine', 'ejs');

    app.get('/', (req, res) => {
        console.log("Home Page");
        res.render('Home');
    });

    app.get('/about', (req, res) => {
        console.log("Info Page");
        res.render('Info');
    });

    app.get('/records', (req, res) => {
        const user = req.session.user; // Fetch from session
        if (!user || !user.uuid) {
            return res.status(400).send('User UUID not found');
        }
        res.render('records-ride', { uuid: user.uuid });
    });


    app.get('/login', (req, res) => {
        console.log("Login Page");
        res.render('Login');
    });

    app.get('/contact', (req, res) => {
        console.log("Contact Page");
        res.render('Contact');
    });

    app.get('/signup', (req, res) => {
        console.log("Signup Page");
        res.render('Signup', { error: null });
    });

    app.get('/profile', (req, res) => {
        const user = req.session.user; // Fetch from session
        if (!user || !user.uuid) {
            return res.status(400).send('User UUID not found');
        }
        res.render('profile', { username: user.username, uuid: user.uuid });
    });

    app.post('/submitFeedback', async (req, res) => {
        try {
            const { feedbackText } = req.body;
    
            if (!req.session.user) {
                return res.status(400).send('Please log in to submit feedback.');
            }
    
            const feedback = new Feedback({
                username: req.session.user.username,
                feedbackText
            });
    
            await feedback.save();
            res.json({ success: true, message: 'Thank you for your feedback!' });
    
        } catch (error) {
            console.error('Error submitting feedback:', error);
            res.status(500).json({ success: false, message: 'Error submitting feedback' });
        }
    });
    
        
    app.get('/driverlogin', (req, res) => {
        console.log("DriverLogin Page");
        res.render('DriverLogin',{ error: null });
    });

    app.get('/driversignup', (req, res) => {
        console.log("DriverSignup Page");
        res.render('DriverSignup', { error: null }); // Pass error as null initially
    });

    app.get('/driverprofile', (req, res) => {
        console.log("Driver Page");
        res.render('Driverprofile');
    });

    app.get('/driverRecord', (req, res) => {
        console.log("Driver Record");
        res.render('driverRecord');
    });

    app.post("/signup", async (req, res) => {
        const { uname, psw } = req.body;

        try {
            if (!uname || !psw) {
                return res.status(400).send('Username and password are required.');
            }

            // Check if the user already exists
            const existingUser = await User.findOne({ uname });
            if (existingUser) {
                return res.status(400).send('User already exists. Please choose a different username.');
            }

            // Hash the password using bcrypt
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(psw, saltRounds);

            // Generate UUID for the new user
            const userUUID = uuidv4();

            // Create a new user with UUID
            const newUser = new User({
                uname,
                pwd: hashedPassword,
                uuid: userUUID // Add the UUID field
            });

            // Save the new user to the database
            await newUser.save();

            // Redirect or render login page after signup
            res.render('Login');
        } catch (error) {
            console.error('Error signing up user:', error);
            res.status(500).send('Error signing up user');
        }
    });

    app.post("/login", async (req, res) => {
        const { username, pwd } = req.body;
        try {
            const user = await User.findOne({ uname: username });

            if (!user) {
                return res.status(404).send('User not found');
            }

            const validPassword = await bcrypt.compare(pwd, user.pwd);
            if (!validPassword) {
                return res.status(401).send('Invalid password');
            }

            // Store user details in the session
            req.session.user = { uuid: user.uuid, username: user.uname };

            // Redirect to profile page
            res.render('Profile', { username: user.uname, uuid: user.uuid });
        } catch (error) {
            console.error('Error logging in:', error);
            res.status(500).send('Error logging in');
        }
    });

    // Middleware for logging requests
    app.use((req, res, next) => {
        console.log("Received request body:", req.body);
        next();
    });

    app.post("/driverlogin", async (req, res) => {
        const { duname, dpwd } = req.body;

        try {
            // Find the driver in the database
            const driver = await Driver.findOne({ duname });

            // If driver does not exist
            if (!driver) {
                return res.status(404).send('Driver not found');
            }

            // Trim and normalize whitespace in the submitted password
            const submittedPassword = dpwd.trim();

            // Trim and normalize whitespace in the hashed password from the database
            const databasePassword = driver.dpwd.trim();

            // Log information for debugging
            console.log('Submitted password:', submittedPassword);
            console.log('Length of submitted password:', submittedPassword.length);
            console.log('Hashed password from database:', databasePassword);
            console.log('Length of hashed password from database:', databasePassword.length);
            console.log('Comparing passwords...');

            // Compare the passwords after converting both to the same format and encoding
            const validPassword = await bcrypt.compare(submittedPassword, databasePassword);

            // Log the result of the comparison
            console.log('Is password valid?', validPassword);

            // If passwords match
            if (validPassword) {
                console.log('Password is valid');
                
                // Update the driver's availability status to true
                await Driver.findByIdAndUpdate(driver._id, { available: true });

                // Render the Driverprofile page
                res.render('Driverprofile', { username: driver.duname });
            } else {
                console.log('Invalid password');
                res.status(401).send('Invalid password');
            }
        } catch (error) {
            console.error('Error logging in:', error);
            res.status(500).send('Error logging in');
        }
    });

    app.post("/driversignup", async (req, res) => {
        const { uname, psw } = req.body;

        try {
            if (!uname || !psw) {
                return res.status(400).send('Username and password are required.');
            }

            // Check if the driver already exists in the database
            const existingDriver = await Driver.findOne({ duname: uname });
            if (existingDriver) {
                return res.status(400).send('Driver already exists. Please choose a different username.');
            }

            // Hash the password using bcrypt
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(psw, saltRounds);

            // Create a new driver with hashed password
            const newDriver = new Driver({
                duname: uname,
                dpwd: hashedPassword
            });

            // Save the new driver to the database
            console.log("Saving new driver...");
            await newDriver.save();
            console.log("Driver registered successfully!");
            res.render('DriverLogin');
        } catch (error) {
            console.error('Error registering driver:', error);
            res.status(500).send('Error registering driver');
        }
    });

    app.use((req, res, next) => {
        console.log("Received request body:", req.body);
        next();
    });

    app.use((err, req, res, next) => {
        console.error('Error:', err);
        res.status(500).send(`Something broke! Error: ${err.message}`);
    });

    const PORT = 8001;
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
