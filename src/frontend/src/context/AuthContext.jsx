import { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'
import toast from 'react-hot-toast'

const AuthContext = createContext()

const API_BASE_URL = 'http://localhost:3000'

// Configure axios defaults
axios.defaults.baseURL = API_BASE_URL
axios.interceptors.request.use((config) => {
    const token = localStorage.getItem('token')
    if (token) {
        config.headers.Authorization = `Bearer ${token}`
    }
    return config
})

axios.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token')
            localStorage.removeItem('user')
            window.location.href = '/login'
        }
        return Promise.reject(error)
    }
)

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null)
    const [loading, setLoading] = useState(true)
    const [tempToken, setTempToken] = useState(null)

    useEffect(() => {
        const token = localStorage.getItem('token')
        const userData = localStorage.getItem('user')

        if (token && userData) {
            setUser(JSON.parse(userData))
        }
        setLoading(false)
    }, [])

    const login = async (email, password) => {
        try {
            console.log('🌐 Making login request to backend...')
            const response = await axios.post('/login', { email, password })
            console.log('📡 Backend response:', response.data)

            // Check if MFA is enabled and required
            if (response.data.requiresMFA) {
                console.log('🔒 MFA required for this user')
                setTempToken(response.data.tempToken)
                return { requiresMFA: true }
            }

            const { token, user: userData } = response.data
            console.log('👤 User data received:', userData)
            
            localStorage.setItem('token', token)
            localStorage.setItem('user', JSON.stringify(userData))
            setUser(userData)

            toast.success(`Welcome to ForensicLink, ${userData.name}!`)
            return { success: true }
        } catch (error) {
            console.error('🚨 Login request failed:', error)
            console.error('Response status:', error.response?.status)
            console.error('Response data:', error.response?.data)
            console.error('Request config:', error.config)
            
            const message = error.response?.data?.error || 'Login failed'
            toast.error(message)
            throw new Error(message)
        }
    }

    const verifyMFA = async (mfaToken) => {
        try {
            const response = await axios.post('/verify', {
                tempToken,
                mfaToken
            })

            const { token, user: userData } = response.data
            localStorage.setItem('token', token)
            localStorage.setItem('user', JSON.stringify(userData))
            setUser(userData)
            setTempToken(null)

            toast.success('MFA verification successful!')
            return { success: true }
        } catch (error) {
            const message = error.response?.data?.error || 'MFA verification failed'
            toast.error(message)
            throw new Error(message)
        }
    }

    const register = async (formData) => {
        try {
            console.log('📝 Attempting registration for:', formData.email);
            
            // Remove confirmPassword before sending to backend
            const { confirmPassword, ...registrationData } = formData;
            
            const response = await fetch(`${API_BASE_URL}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(registrationData),
            });

            const data = await response.json();
            console.log('📝 Registration response:', data);

            if (response.ok) {
                console.log('✅ Registration completed successfully');
                toast.success(data.message || 'Registration successful! Your account is pending admin approval.');
                return { success: true };
            } else {
                console.error('❌ Registration failed:', data.error);
                toast.error(data.error || 'Registration failed');
                return { success: false, error: data.error };
            }
        } catch (error) {
            console.error('❌ Registration error:', error);
            toast.error('Registration failed. Please try again.');
            return { success: false, error: 'Registration failed' };
        }    
    }

    const logout = () => {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        setUser(null)
        setTempToken(null)
        toast.success('Logged out successfully')
    }

    const value = {
        user,
        loading,
        tempToken,
        login,
        verifyMFA,
        register,
        logout
    }

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    )
}

export function useAuth() {
    const context = useContext(AuthContext)
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider')
    }
    return context
}