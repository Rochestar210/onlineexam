// Get this from your Firebase project settings
const firebaseConfig = {
  apiKey: "AIzaSyBe857kGYoLQJxmLFpUcPS8jZtWxkFYBlk",
  authDomain: "onlineexam-99eb5.firebaseapp.com",
  projectId: "onlineexam-99eb5",
  storageBucket: "onlineexam-99eb5.firebasestorage.app",
  messagingSenderId: "474888464500",
  appId: "1:474888464500:web:7414d4dbd34e4a88898921"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Initialize services
const auth = firebase.auth();
const db = firebase.firestore();
const storage = firebase.storage();