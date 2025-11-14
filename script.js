// =============================================
// FIREBASE CONFIGURATION & INITIALIZATION
// =============================================

// Firebase services (initialized in firebase-config.js)
const auth = firebase.auth();
const db = firebase.firestore();
const storage = firebase.storage();

let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// =============================================
// FIREBASE DATABASE FUNCTIONS
// =============================================

// User Registration with Firebase Auth + Firestore
async function registerUser(userData) {
    try {
        console.log('Starting user registration:', userData.email);
        
        // 1. Create user in Firebase Authentication
        const userCredential = await auth.createUserWithEmailAndPassword(
            userData.email, 
            userData.password
        );
        const userId = userCredential.user.uid;
        console.log('Firebase Auth user created:', userId);

        // 2. Prepare user data for Firestore (remove password)
        const { password, ...userDataWithoutPassword } = userData;
        
        // 3. Save user data to Firestore
        await db.collection('users').doc(userId).set({
            ...userDataWithoutPassword,
            uid: userId,
            createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            emailVerified: false
        });
        
        console.log('User data saved to Firestore');
        return userId;
        
    } catch (error) {
        console.error('Registration error:', error);
        throw error;
    }
}

// User Login with Firebase Auth
async function loginUser(email, password) {
    try {
        console.log('Attempting login:', email);
        
        // 1. Sign in with Firebase Authentication
        const userCredential = await auth.signInWithEmailAndPassword(email, password);
        const userId = userCredential.user.uid;
        console.log('Firebase Auth login successful:', userId);

        // 2. Get user data from Firestore
        const userDoc = await db.collection('users').doc(userId).get();
        
        if (!userDoc.exists) {
            throw new Error('User data not found in database');
        }

        const userData = userDoc.data();
        console.log('User data retrieved:', userData.username);
        
        return { 
            uid: userId,
            ...userData 
        };
        
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

// Get user by username
async function getUserByUsername(username) {
    try {
        const snapshot = await db.collection('users')
            .where('username', '==', username)
            .limit(1)
            .get();
        
        if (snapshot.empty) {
            return null;
        }
        
        const doc = snapshot.docs[0];
        return { id: doc.id, ...doc.data() };
    } catch (error) {
        throw error;
    }
}

// Get user by email
async function getUserByEmail(email) {
    try {
        const snapshot = await db.collection('users')
            .where('email', '==', email)
            .limit(1)
            .get();
        
        if (snapshot.empty) {
            return null;
        }
        
        const doc = snapshot.docs[0];
        return { id: doc.id, ...doc.data() };
    } catch (error) {
        throw error;
    }
}

// Get all users by role
async function getAllUsers(role = null) {
    try {
        let query = db.collection('users');
        
        if (role) {
            query = query.where('role', '==', role);
        }
        
        const snapshot = await query.get();
        return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (error) {
        throw error;
    }
}

// Update user profile
async function updateUserProfile(userId, userData) {
    try {
        await db.collection('users').doc(userId).update({
            ...userData,
            updatedAt: firebase.firestore.FieldValue.serverTimestamp()
        });
    } catch (error) {
        throw error;
    }
}

// Delete user
async function deleteUser(userId) {
    try {
        await db.collection('users').doc(userId).delete();
        // Note: You might also want to delete the auth user
        // await auth.currentUser.delete();
    } catch (error) {
        throw error;
    }
}

// Exam Functions
async function createExam(examData) {
    try {
        const docRef = await db.collection('exams').add({
            ...examData,
            createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            isActive: true
        });
        return docRef.id;
    } catch (error) {
        throw error;
    }
}

async function getExam(examId) {
    try {
        const doc = await db.collection('exams').doc(examId).get();
        if (!doc.exists) {
            return null;
        }
        return { id: doc.id, ...doc.data() };
    } catch (error) {
        throw error;
    }
}

async function getExamsBySubject(subject) {
    try {
        const snapshot = await db.collection('exams')
            .where('subject', '==', subject)
            .where('isActive', '==', true)
            .get();
        
        return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (error) {
        throw error;
    }
}

async function getAllExams() {
    try {
        const snapshot = await db.collection('exams')
            .where('isActive', '==', true)
            .get();
        
        return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (error) {
        throw error;
    }
}

// Result Functions
async function submitExamResult(resultData) {
    try {
        const docRef = await db.collection('results').add({
            ...resultData,
            submittedAt: firebase.firestore.FieldValue.serverTimestamp()
        });
        return docRef.id;
    } catch (error) {
        throw error;
    }
}

async function getStudentResults(studentUsername) {
    try {
        const snapshot = await db.collection('results')
            .where('studentUsername', '==', studentUsername)
            .orderBy('submittedAt', 'desc')
            .get();
        
        return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (error) {
        throw error;
    }
}

// =============================================
// VALIDATION FUNCTIONS
// =============================================

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email.includes('@')) {
        return { isValid: false, message: 'Email must contain @ symbol' };
    }
    return { isValid: emailRegex.test(email), message: 'Please enter a valid email address' };
}

function validateLesothoPhone(phone) {
    if (!phone) return { isValid: true, message: '' };
    
    const phoneRegex = /^\+266\s?[56]\d{7}$/;
    const isValid = phoneRegex.test(phone);
    
    return { 
        isValid: isValid, 
        message: isValid ? '' : 'Phone must be Lesotho format: +266 5XXXXXXX or +266 6XXXXXXX' 
    };
}

function validatePassword(password) {
    if (password.length < 6) {
        return { isValid: false, message: 'Password must be at least 6 characters long' };
    }
    return { isValid: true, message: '' };
}

// =============================================
// UTILITY FUNCTIONS
// =============================================

function showAlert(message, type = 'info') {
    // Remove any existing alerts
    const existingAlerts = document.querySelectorAll('.alert');
    existingAlerts.forEach(alert => alert.remove());
    
    // Create new alert
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    alertDiv.style.cssText = `
        padding: 12px 16px;
        border-radius: 6px;
        margin: 1rem 0;
        font-weight: 500;
        border: 1px solid transparent;
    `;
    
    // Style based on type
    if (type === 'success') {
        alertDiv.style.background = '#d4edda';
        alertDiv.style.color = '#155724';
        alertDiv.style.borderColor = '#c3e6cb';
    } else if (type === 'error') {
        alertDiv.style.background = '#f8d7da';
        alertDiv.style.color = '#721c24';
        alertDiv.style.borderColor = '#f5c6cb';
    } else {
        alertDiv.style.background = '#cce7ff';
        alertDiv.style.color = '#004085';
        alertDiv.style.borderColor = '#b3d7ff';
    }
    
    // Insert at top of form
    const form = document.querySelector('form');
    if (form) {
        form.insertBefore(alertDiv, form.firstChild);
    } else {
        // If no form, insert at top of auth container
        const authContainer = document.querySelector('.auth-container');
        if (authContainer) {
            authContainer.insertBefore(alertDiv, authContainer.firstChild);
        }
    }
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

function getSubjectName(subjectKey) {
    const subjects = {
        'web-design': 'Web Design',
        'business-management': 'Business Management',
        'business-communication': 'Business Communication',
        'algebra-math': 'Algebra & Mathematics',
        'programming': 'Programming',
        'computer-applications': 'Computer Applications'
    };
    return subjects[subjectKey] || subjectKey;
}

// =============================================
// AUTHENTICATION FUNCTIONS
// =============================================

// Student Registration
function initializeStudentRegistration() {
    const studentRegisterForm = document.getElementById('studentRegisterForm');
    if (studentRegisterForm) {
        studentRegisterForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const name = document.getElementById('regStudentName').value.trim();
            const email = document.getElementById('regStudentEmail').value.trim();
            const username = document.getElementById('regStudentUsername').value.trim();
            const password = document.getElementById('regStudentPassword').value;
            const course = document.getElementById('regStudentCourse').value;

            // Validation
            if (!name || !email || !username || !password || !course) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }

            const emailValidation = validateEmail(email);
            if (!emailValidation.isValid) {
                showAlert(emailValidation.message, 'error');
                return;
            }

            const passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid) {
                showAlert(passwordValidation.message, 'error');
                return;
            }

            try {
                // Check if username already exists
                const existingUser = await getUserByUsername(username);
                if (existingUser) {
                    showAlert('Username already exists! Please choose a different one.', 'error');
                    return;
                }

                // Check if email already exists
                const existingEmail = await getUserByEmail(email);
                if (existingEmail) {
                    showAlert('Email already registered! Please use a different email.', 'error');
                    return;
                }

                // Create user data object
                const userData = {
                    username: username,
                    password: password, // This will be used for Firebase Auth
                    role: 'student',
                    name: name,
                    email: email,
                    course: course,
                    phone: '',
                    registrationDate: new Date().toISOString()
                };

                // Register user with Firebase
                const userId = await registerUser(userData);
                
                showAlert('Registration successful! You can now login.', 'success');
                
                // Switch to login form after successful registration
                setTimeout(() => {
                    document.getElementById('studentRegisterSection').style.display = 'none';
                    document.getElementById('studentLoginSection').style.display = 'block';
                    studentRegisterForm.reset();
                }, 2000);

            } catch (error) {
                console.error('Registration error:', error);
                let errorMessage = 'Registration failed. ';
                
                if (error.code === 'auth/email-already-in-use') {
                    errorMessage += 'Email is already registered.';
                } else if (error.code === 'auth/weak-password') {
                    errorMessage += 'Password is too weak.';
                } else if (error.code === 'auth/invalid-email') {
                    errorMessage += 'Invalid email address.';
                } else {
                    errorMessage += error.message;
                }
                
                showAlert(errorMessage, 'error');
            }
        });
    }
}

// Student Login
function initializeStudentLogin() {
    const studentLoginForm = document.getElementById('studentLoginForm');
    if (studentLoginForm) {
        studentLoginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('studentUsername').value.trim();
            const password = document.getElementById('studentPassword').value;

            if (!email || !password) {
                showAlert('Please fill in all fields', 'error');
                return;
            }

            try {
                // Login with Firebase Authentication
                const user = await loginUser(email, password);
                
                // Verify user role
                if (user.role !== 'student') {
                    showAlert('Access denied. This is for students only.', 'error');
                    await auth.signOut();
                    return;
                }

                // Store user in localStorage
                currentUser = user;
                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                
                showAlert('Login successful! Redirecting to dashboard...', 'success');
                
                // Redirect to student dashboard
                setTimeout(() => {
                    window.location.href = 'student-dashboard.html';
                }, 1500);

            } catch (error) {
                console.error('Login error:', error);
                let errorMessage = 'Login failed. ';
                
                if (error.code === 'auth/user-not-found') {
                    errorMessage += 'No account found with this email.';
                } else if (error.code === 'auth/wrong-password') {
                    errorMessage += 'Incorrect password.';
                } else if (error.code === 'auth/invalid-email') {
                    errorMessage += 'Invalid email address.';
                } else {
                    errorMessage += error.message;
                }
                
                showAlert(errorMessage, 'error');
            }
        });
    }
}

// Examiner Registration
function initializeExaminerRegistration() {
    const examinerRegisterForm = document.getElementById('examinerRegisterForm');
    if (examinerRegisterForm) {
        examinerRegisterForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const name = document.getElementById('regExaminerName').value.trim();
            const email = document.getElementById('regExaminerEmail').value.trim();
            const username = document.getElementById('regExaminerUsername').value.trim();
            const password = document.getElementById('regExaminerPassword').value;
            const subject = document.getElementById('regExaminerSubject').value;
            const phone = document.getElementById('regExaminerPhone').value.trim();

            if (!name || !email || !username || !password || !subject) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }

            const emailValidation = validateEmail(email);
            if (!emailValidation.isValid) {
                showAlert(emailValidation.message, 'error');
                return;
            }

            const phoneValidation = validateLesothoPhone(phone);
            if (!phoneValidation.isValid) {
                showAlert(phoneValidation.message, 'error');
                return;
            }

            const passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid) {
                showAlert(passwordValidation.message, 'error');
                return;
            }

            try {
                // Check if username already exists
                const existingUser = await getUserByUsername(username);
                if (existingUser) {
                    showAlert('Username already exists!', 'error');
                    return;
                }

                // Check if email already exists
                const existingEmail = await getUserByEmail(email);
                if (existingEmail) {
                    showAlert('Email already registered!', 'error');
                    return;
                }

                const userData = {
                    username: username,
                    password: password,
                    role: 'examiner',
                    subject: subject,
                    name: name,
                    email: email,
                    phone: phone,
                    registrationDate: new Date().toISOString()
                };

                await registerUser(userData);
                
                showAlert('Examiner registration successful! Please login.', 'success');
                
                setTimeout(() => {
                    document.getElementById('examinerRegisterSection').style.display = 'none';
                    document.getElementById('examinerLoginSection').style.display = 'block';
                    examinerRegisterForm.reset();
                }, 2000);

            } catch (error) {
                console.error('Registration error:', error);
                let errorMessage = 'Registration failed. ';
                
                if (error.code === 'auth/email-already-in-use') {
                    errorMessage += 'Email is already registered.';
                } else {
                    errorMessage += error.message;
                }
                
                showAlert(errorMessage, 'error');
            }
        });
    }
}

// Examiner Login
function initializeExaminerLogin() {
    const examinerLoginForm = document.getElementById('examinerLoginForm');
    if (examinerLoginForm) {
        examinerLoginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('examinerUsername').value.trim();
            const password = document.getElementById('examinerPassword').value;
            const subject = document.getElementById('examinerSubject').value;

            if (!email || !password || !subject) {
                showAlert('Please fill in all fields', 'error');
                return;
            }

            try {
                const user = await loginUser(email, password);
                
                if (user.role !== 'examiner') {
                    showAlert('Access denied. This is for examiners only.', 'error');
                    await auth.signOut();
                    return;
                }

                if (user.subject !== subject) {
                    showAlert('Subject mismatch! Please select the correct subject.', 'error');
                    await auth.signOut();
                    return;
                }

                currentUser = user;
                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                
                showAlert('Login successful! Redirecting...', 'success');
                
                setTimeout(() => {
                    window.location.href = 'examiner-dashboard.html';
                }, 1500);

            } catch (error) {
                console.error('Login error:', error);
                showAlert('Login failed. Please check your credentials.', 'error');
            }
        });
    }
}

// Admin Registration
function initializeAdminRegistration() {
    const adminRegisterForm = document.getElementById('adminRegisterForm');
    if (adminRegisterForm) {
        adminRegisterForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const name = document.getElementById('regAdminName').value.trim();
            const email = document.getElementById('regAdminEmail').value.trim();
            const username = document.getElementById('regAdminUsername').value.trim();
            const password = document.getElementById('regAdminPassword').value;
            const phone = document.getElementById('regAdminPhone').value.trim();

            if (!name || !email || !username || !password) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }

            const emailValidation = validateEmail(email);
            if (!emailValidation.isValid) {
                showAlert(emailValidation.message, 'error');
                return;
            }

            const phoneValidation = validateLesothoPhone(phone);
            if (!phoneValidation.isValid) {
                showAlert(phoneValidation.message, 'error');
                return;
            }

            const passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid) {
                showAlert(passwordValidation.message, 'error');
                return;
            }

            try {
                const existingUser = await getUserByUsername(username);
                if (existingUser) {
                    showAlert('Username already exists!', 'error');
                    return;
                }

                const existingEmail = await getUserByEmail(email);
                if (existingEmail) {
                    showAlert('Email already registered!', 'error');
                    return;
                }

                const userData = {
                    username: username,
                    password: password,
                    role: 'admin',
                    name: name,
                    email: email,
                    phone: phone,
                    registrationDate: new Date().toISOString()
                };

                await registerUser(userData);
                
                showAlert('Admin registration successful! Please login.', 'success');
                
                setTimeout(() => {
                    document.getElementById('adminRegisterSection').style.display = 'none';
                    document.getElementById('adminLoginSection').style.display = 'block';
                    adminRegisterForm.reset();
                }, 2000);

            } catch (error) {
                console.error('Registration error:', error);
                showAlert('Registration failed: ' + error.message, 'error');
            }
        });
    }
}

// Admin Login
function initializeAdminLogin() {
    const adminLoginForm = document.getElementById('adminLoginForm');
    if (adminLoginForm) {
        adminLoginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('adminUsername').value.trim();
            const password = document.getElementById('adminPassword').value;

            if (!email || !password) {
                showAlert('Please fill in all fields', 'error');
                return;
            }

            try {
                const user = await loginUser(email, password);
                
                if (user.role !== 'admin') {
                    showAlert('Access denied. This is for administrators only.', 'error');
                    await auth.signOut();
                    return;
                }

                currentUser = user;
                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                
                showAlert('Login successful! Redirecting...', 'success');
                
                setTimeout(() => {
                    window.location.href = 'admin-dashboard.html';
                }, 1500);

            } catch (error) {
                console.error('Login error:', error);
                showAlert('Login failed. Please check your credentials.', 'error');
            }
        });
    }
}

// =============================================
// UI & NAVIGATION FUNCTIONS
// =============================================

function initializeHamburgerMenu() {
    const hamburgerBtn = document.querySelector('.hamburger-btn');
    const navMenu = document.querySelector('.nav-menu');
    if (hamburgerBtn && navMenu) {
        hamburgerBtn.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            const spans = hamburgerBtn.querySelectorAll('span');
            if (navMenu.classList.contains('active')) {
                spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translate(7px, -6px)';
            } else {
                spans[0].style.transform = 'none';
                spans[1].style.opacity = '1';
                spans[2].style.transform = 'none';
            }
        });
    }
}

function initializeFormToggles() {
    // Student form toggles
    const showStudentRegister = document.getElementById('showStudentRegister');
    const studentRegisterSection = document.getElementById('studentRegisterSection');
    const studentLoginSection = document.getElementById('studentLoginSection');
    const backToStudentLogin = document.getElementById('backToStudentLogin');

    if (showStudentRegister) {
        showStudentRegister.addEventListener('click', (e) => {
            e.preventDefault();
            studentLoginSection.style.display = 'none';
            studentRegisterSection.style.display = 'block';
        });
    }
    if (backToStudentLogin) {
        backToStudentLogin.addEventListener('click', (e) => {
            e.preventDefault();
            studentRegisterSection.style.display = 'none';
            studentLoginSection.style.display = 'block';
        });
    }

    // Examiner form toggles
    const showExaminerRegister = document.getElementById('showExaminerRegister');
    const examinerRegisterSection = document.getElementById('examinerRegisterSection');
    const examinerLoginSection = document.getElementById('examinerLoginSection');
    const backToExaminerLogin = document.getElementById('backToExaminerLogin');

    if (showExaminerRegister) {
        showExaminerRegister.addEventListener('click', (e) => {
            e.preventDefault();
            examinerLoginSection.style.display = 'none';
            examinerRegisterSection.style.display = 'block';
        });
    }
    if (backToExaminerLogin) {
        backToExaminerLogin.addEventListener('click', (e) => {
            e.preventDefault();
            examinerRegisterSection.style.display = 'none';
            examinerLoginSection.style.display = 'block';
        });
    }

    // Admin form toggles
    const showAdminRegister = document.getElementById('showAdminRegister');
    const adminRegisterSection = document.getElementById('adminRegisterSection');
    const adminLoginSection = document.getElementById('adminLoginSection');
    const backToAdminLogin = document.getElementById('backToAdminLogin');

    if (showAdminRegister) {
        showAdminRegister.addEventListener('click', (e) => {
            e.preventDefault();
            adminLoginSection.style.display = 'none';
            adminRegisterSection.style.display = 'block';
        });
    }
    if (backToAdminLogin) {
        backToAdminLogin.addEventListener('click', (e) => {
            e.preventDefault();
            adminRegisterSection.style.display = 'none';
            adminLoginSection.style.display = 'block';
        });
    }
}

function clearAllForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => form.reset());
}

function disableAutofill() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.setAttribute('autocomplete', 'off');
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.setAttribute('autocomplete', 'off');
            input.setAttribute('autocorrect', 'off');
            input.setAttribute('autocapitalize', 'off');
            input.setAttribute('spellcheck', 'false');
        });
    });
}

// =============================================
// PASSWORD RESET
// =============================================

async function showForgotPassword() {
    const email = prompt('Please enter your registered email address:');
    if (!email) return;

    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
        alert(emailValidation.message);
        return;
    }

    try {
        await auth.sendPasswordResetEmail(email);
        alert('Password reset email sent! Please check your inbox.');
    } catch (error) {
        alert('Error sending reset email: ' + error.message);
    }
}

// =============================================
// LOGOUT FUNCTION
// =============================================

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        auth.signOut().then(() => {
            currentUser = null;
            localStorage.removeItem('currentUser');
            window.location.href = 'index.html';
        });
    }
}

// =============================================
// MAIN INITIALIZATION
// =============================================

async function initializeApp() {
    try {
        console.log('Initializing application...');
        
        // Initialize UI components
        initializeHamburgerMenu();
        initializeFormToggles();
        disableAutofill();
        clearAllForms();
        
        // Initialize authentication forms
        initializeStudentRegistration();
        initializeStudentLogin();
        initializeExaminerRegistration();
        initializeExaminerLogin();
        initializeAdminRegistration();
        initializeAdminLogin();
        
        console.log('Application initialized successfully');
        
    } catch (error) {
        console.error('Error initializing application:', error);
        showAlert('System initialization error. Please refresh the page.', 'error');
    }
}

// =============================================
// GLOBAL FUNCTIONS
// =============================================

window.logout = logout;
window.showForgotPassword = showForgotPassword;
window.clearAllForms = clearAllForms;

// =============================================
// START APPLICATION
// =============================================

document.addEventListener('DOMContentLoaded', initializeApp);