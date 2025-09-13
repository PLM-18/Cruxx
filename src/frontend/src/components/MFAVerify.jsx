import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Shield, Smartphone } from 'lucide-react'
import toast from 'react-hot-toast'

export default function MFAVerify() {
    const [mfaToken, setMfaToken] = useState('')
    const [loading, setLoading] = useState(false)
    const { verifyMFA, tempToken } = useAuth()
    const navigate = useNavigate()

    const handleSubmit = async (e) => {
        e.preventDefault()

        if (!tempToken) {
            toast.error('No temporary token found. Please login again.')
            navigate('/login')
            return
        }

        if (mfaToken.length !== 6) {
            toast.error('Please enter a valid 6-digit code')
            return
        }

        setLoading(true)

        try {
            await verifyMFA(mfaToken)
            navigate('/dashboard')
        } catch (error) {
            // Error handling is done in the context
        } finally {
            setLoading(false)
        }
    }

    const handleTokenChange = (e) => {
        const value = e.target.value.replace(/\D/g, '').slice(0, 6)
        setMfaToken(value)
    }

    if (!tempToken) {
        navigate('/login')
        return null
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
            <div className="max-w-md w-full mx-4">
                <div className="bg-white rounded-2xl shadow-xl p-8">
                    {/* Header */}
                    <div className="text-center mb-8">
                        <div className="flex justify-center mb-4">
                            <div className="bg-blue-600 rounded-full p-3">
                                <Shield className="h-8 w-8 text-white" />
                            </div>
                        </div>
                        <h2 className="text-2xl font-bold text-gray-900">Two-Factor Authentication</h2>
                        <p className="text-gray-600 mt-2">
                            Enter the 6-digit code from your authenticator app
                        </p>
                    </div>

                    {/* MFA Illustration */}
                    <div className="flex justify-center mb-6">
                        <div className="bg-gray-100 rounded-lg p-4">
                            <Smartphone className="h-12 w-12 text-gray-600" />
                        </div>
                    </div>

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                Authentication Code
                            </label>
                            <input
                                type="text"
                                value={mfaToken}
                                onChange={handleTokenChange}
                                required
                                className="input-field text-center text-2xl tracking-widest font-mono"
                                placeholder="000000"
                                maxLength={6}
                                autoComplete="off"
                            />
                            <p className="text-xs text-gray-500 mt-2 text-center">
                                Enter the code from Google Authenticator or similar app
                            </p>
                        </div>

                        <button
                            type="submit"
                            disabled={loading || mfaToken.length !== 6}
                            className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {loading ? (
                                <div className="flex items-center justify-center">
                                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                                    Verifying...
                                </div>
                            ) : (
                                'Verify Code'
                            )}
                        </button>
                    </form>

                    {/* Footer */}
                    <div className="mt-6 text-center">
                        <p className="text-sm text-gray-600">
                            Having trouble? Contact your system administrator
                        </p>
                    </div>

                    {/* Help */}
                    <div className="mt-4 p-3 bg-blue-50 rounded-lg border border-blue-200">
                        <p className="text-xs text-blue-800">
                            <strong>Tip:</strong> The code refreshes every 30 seconds. Make sure you're using the current code.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    )
}