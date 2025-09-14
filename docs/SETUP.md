> *This document provides setup instructions for running both the Node.js backend and React Vite frontend of your project. Optionally, you can use Docker for containerized deployment.*

# Setup Instructions

Follow the steps below to set up and run the project.

---

## 📦 Requirements

- Node.js v18+
- npm (comes with Node.js)

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone git@github.com:PLM-18/Cruxx.git
cd Cruxx/src
```

### 2. Install Backend Dependencies
```bash
cd backend
npm install
```

### 3. Install Frontend Dependencies
```bash
cd ../frontend
npm install
```

---

## ▶️ Running the Project

### 1. Start the Backend
```bash
cd backend
npm run dev
```

### 2. Start the Frontend
```bash
cd ../frontend
npm run dev
```
The frontend will typically be available at [http://localhost:5173](http://localhost:5173) and the backend at [http://localhost:3000](http://localhost:3000) (adjust ports as needed).


