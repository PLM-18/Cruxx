# ForensicLink - Usage Guide

**ForensicLink** is a secure digital evidence collaboration platform designed for cybersecurity professionals and digital forensics investigators. This guide will walk you through how to use the platform effectively.

---

## ▶️ Running the Application

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn package manager

### Starting the Application

1. **Start the Backend Server:**
   ```bash
   cd Cruxx/src/backend
   npm install
   npm start
   ```
   The backend server will start on `http://localhost:3000`

2. **Start the Frontend Application:**
   ```bash
   cd Cruxx/src/frontend
   npm install
   npm run dev
   ```
   The frontend will start on `http://localhost:5173`

3. **Access the Application:**
   Open your web browser and navigate to `http://localhost:5173`

---

## 🖥️ How to Use

### 1. **Initial Login (Admin Setup)**
When you first access ForensicLink, use the default admin credentials:
- **Email:** `admin@forensiclink.com`
- **Password:** `forensiclink2024`

⚠️ **Important:** Change these credentials immediately after first login for security.

### 2. **User Registration & Management**

#### **For New Users:**
1. Click **"Create Account"** on the login page
2. Fill in your details:
   - First Name and Last Name
   - Professional Email Address
   - Secure Password (must contain uppercase, lowercase, number, and special character)
   - Confirm Password
3. Submit the registration form
4. Wait for admin approval (your account will be pending until approved)

#### **For Admins - User Management:**
1. Navigate to **"Manage Users"** from the dashboard
2. View all registered users and their approval status
3. **Approve Users:** Click the approve button next to pending users
4. **Assign Roles:** Set user roles (Admin, Manager, Analyst)
5. **Revoke Access:** Remove user permissions if needed

### 3. **Workspace Management**

#### **Creating Workspaces (Admin Only):**
1. Go to **"Workspace Manager"** from the dashboard
2. Click **"Create New Workspace"**
3. Fill in workspace details:
   - **Workspace Name:** Descriptive name for the investigation
   - **Description:** Brief overview of the case
   - **Case Number:** Unique identifier (optional)
   - **Assigned Manager:** Select a user with Manager role
4. Click **"Create Workspace"**

#### **Accessing Workspaces:**
1. From the dashboard, view your available workspaces
2. Click on a workspace to enter
3. If prompted, enter the workspace password for security

#### **Managing Workspace Members:**
1. Inside a workspace, go to **"Members"** section
2. **Add Members:** Click "Add Member" and select from available users
3. **Assign Roles:** Set member roles (Manager or Analyst)
4. **Remove Members:** Use the remove button (Managers and Admins only)

### 4. **Evidence Management**

#### **Uploading Evidence:**
1. Navigate to a workspace
2. Go to the **"Evidence"** section
3. Click **"Upload Evidence"**
4. Select files to upload (supports pdfs)
5. Add description and tags for the evidence
6. Submit the upload

**Supported File Types:**
- Documents: PDF 
    (may be extended at a later stage to support other file types)

#### **Viewing Evidence:**
1. In the workspace, browse the evidence list
2. Click on any evidence file to view details
3. Use the **"Download"** button to access files
4. All downloads are logged for audit purposes

#### **Security Features:**
- All evidence files are automatically encrypted
- File integrity is maintained with hash verification
- Access is logged and auditable
- Role-based permissions control who can view/download

### 5. **File Management System**

#### **Document Management:**
1. Navigate to **"File Manager"** from the dashboard
2. **Upload Files:** Use the upload button for each category
3. **View Files:** Click on files to view or download
4. **Organize:** Use search and filtering options

#### **Confidential Files:**
- Special category for sensitive information
- Enhanced encryption and access controls
- Only accessible to authorized personnel
- Requires additional permissions

### 6. **Security Features**

#### **Multi-Factor Authentication (MFA):**
1. From your profile, enable MFA for additional security
2. Scan the QR code with an authenticator app
3. Enter the verification code to complete setup
4. MFA will be required for future logins

#### **Role-Based Access Control:**
- **Admin:** Full system access, user management, workspace creation
- **Manager:** Workspace management, member control, evidence access
- **Analyst:** Evidence viewing, file access within assigned workspaces

### 7. **Analytics & Monitoring**

#### **For Admins and Managers:**
1. Access **"Analytics"** from the dashboard
2. View system usage statistics
3. Monitor user activity logs
4. Review security alerts and anomalies
5. Track file access and downloads

#### **Audit Trail:**
- All user actions are logged
- File access is tracked
- Workspace activities are monitored
- Security events are recorded

---

## 🎥 Demo

Check out our demonstration materials:
- [Demo Video](../demo/demo.mp4) - Complete walkthrough of ForensicLink features
- [Demo Presentation](../demo/demo.pptx) - Overview slides and feature highlights

---

## 📌 Important Notes

### **Security Best Practices:**
1. **Change Default Credentials:** Immediately update the default admin password
2. **Use Strong Passwords:** Ensure all users create secure passwords
3. **Enable MFA:** Activate multi-factor authentication for sensitive accounts
4. **Regular Backups:** Backup the SQLite database regularly
5. **Access Control:** Regularly review user permissions and workspace access

### **File Upload Limitations:**
- Maximum file size: 100MB per evidence file, 10MB for general files
- Supported formats are limited for security reasons
- All files are encrypted automatically upon upload

### **User Workflow:**
1. **New Users:** Register → Wait for approval → Access assigned workspaces
2. **Managers:** Create workspaces → Add members → Manage evidence
3. **Analysts:** Access workspaces → View/download evidence → Collaborate

### **Troubleshooting:**
- **Login Issues:** Check if account is approved by an admin
- **File Upload Errors:** Verify file size and format requirements
- **Access Denied:** Confirm workspace membership and permissions
- **MFA Problems:** Contact admin to reset MFA settings

### **Data Security:**
- All sensitive data is encrypted at rest
- Communications use HTTPS in production
- File integrity is maintained with SHA-256 hashing
- Audit logs track all system activities

### **Browser Requirements:**
- Modern web browser with JavaScript enabled
- Chrome, Firefox, Safari, or Edge (latest versions)
- Cookies and local storage must be enabled

---

## 🚀 Getting Started Quickly

1. **Setup:** Follow the running instructions above
2. **Login:** Use admin credentials to access the system
3. **Create Users:** Register and approve user accounts
4. **Setup Workspace:** Create your first investigation workspace
5. **Upload Evidence:** Add evidence files to begin collaboration
6. **Collaborate:** Invite team members and start investigating

For technical support or advanced configuration, refer to the [SETUP.md](SETUP.md) documentation.
