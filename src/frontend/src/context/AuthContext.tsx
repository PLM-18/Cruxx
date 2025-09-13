import { createContext, useContext, useState, useEffect } from 'react'
import type ReactNode from 'react'
import axios from 'axios'
import type { AxiosResponse } from 'axios'
import toast from 'react-hot-toast'

interface User {
    id: string
    email: string
    name: string
    role: string
    // Add other user properties as needed
}

interface LoginResponse {
    success?: boolean
    requiresMFA?: boolean
    tempToken?: string
    token?: string
    user?: User
}

interface AuthContextType {
    user: User | null
    loading: boolean
    tempToken: string | null
    login: (email: string, password: string) => Promise<LoginResponse>
    verifyMFA: (mfaToken: string) => Promise<{ success: boolean }>
    register: (userData: RegisterData) => Promise<{ success: boolean }>
    logout: () => void
}

interface RegisterData {
    email: string
    password: string
    name: string
    surname: string
    // Add other registration fields as needed
}

interface AuthProviderProps {
    children: ReactNode.ReactNode
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const API_BASE_URL = 'http://localhost:3001'

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
    (response: AxiosResponse) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token')
            localStorage.removeItem('user')
            window.location.href = '/login'
        }
        return Promise.reject(error)
    }
)

export function AuthProvider({ children }: AuthProviderProps): React.ReactElement {
    const [user, setUser] = useState<User | null>(null)
    const [loading, setLoading] = useState<boolean>(true)
    const [tempToken, setTempToken] = useState<string | null>(null)

    useEffect(() => {
        const token = localStorage.getItem('token')
        const userData = localStorage.getItem('user')

        if (token && userData) {
            try {
                setUser(JSON.parse(userData))
            } catch (error) {
                console.error('Error parsing user data:', error)
                localStorage.removeItem('token')
                localStorage.removeItem('user')
            }
        }
        setLoading(false)
    }, [])

    const login = async (email: string, password: string): Promise<LoginResponse> => {
        try {
            const response: AxiosResponse<LoginResponse> = await axios.post('/login', { email, password })

            if (response.data.requiresMFA) {
                setTempToken(response.data.tempToken || null)
                return { requiresMFA: true }
            }

            const { token, user: userData } = response.data
            if (token && userData) {
                localStorage.setItem('token', token)
                localStorage.setItem('user', JSON.stringify(userData))
                setUser(userData)
            }

            toast.success('Login successful!')
            return { success: true }
        } catch (error: any) {
            const message = error.response?.data?.error || 'Login failed'
            toast.error(message)
            throw new Error(message)
        }
    }

    const verifyMFA = async (mfaToken: string): Promise<{ success: boolean }> => {
        try {
            const response: AxiosResponse<{ token: string; user: User }> = await axios.post('/verify', {
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
        } catch (error: any) {
            const message = error.response?.data?.error || 'MFA verification failed'
            toast.error(message)
            throw new Error(message)
        }
    }

    const register = async (userData: RegisterData): Promise<{ success: boolean }> => {
        try {
            await axios.post('/register', userData)
            toast.success('Registration successful! Awaiting admin approval.')
            return { success: true }
        } catch (error: any) {
            const message = error.response?.data?.error || 'Registration failed'
            toast.error(message)
            throw new Error(message)
        }
    }

    const logout = (): void => {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        setUser(null)
        setTempToken(null)
        toast.success('Logged out successfully')
    }

    const value: AuthContextType = {
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

export function useAuth(): AuthContextType {
    const context = useContext(AuthContext)
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider')
    }
    return context
}