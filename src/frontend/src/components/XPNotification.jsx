import { useState, useEffect } from 'react'
import { Star, Trophy, X } from 'lucide-react'

export default function XPNotification({ notification, onClose }) {
    const [isVisible, setIsVisible] = useState(false)

    useEffect(() => {
        if (notification) {
            setIsVisible(true)
            // Auto-dismiss after 5 seconds
            const timer = setTimeout(() => {
                handleClose()
            }, 5000)
            return () => clearTimeout(timer)
        }
    }, [notification])

    const handleClose = () => {
        setIsVisible(false)
        setTimeout(() => {
            if (onClose) onClose()
        }, 300) // Match the transition duration
    }

    if (!notification) return null

    const isAchievement = notification.type === 'achievement'

    return (
        <div className={`fixed top-4 right-4 z-50 transition-all duration-300 transform ${
            isVisible ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'
        }`}>
            <div className={`max-w-sm rounded-lg shadow-lg border-l-4 p-4 ${
                isAchievement 
                    ? 'bg-gradient-to-r from-yellow-50 to-orange-50 border-yellow-400' 
                    : 'bg-gradient-to-r from-blue-50 to-indigo-50 border-blue-400'
            }`}>
                <div className="flex items-start">
                    <div className="flex-shrink-0">
                        {isAchievement ? (
                            <Trophy className="h-6 w-6 text-yellow-600" />
                        ) : (
                            <Star className="h-6 w-6 text-blue-600" />
                        )}
                    </div>
                    <div className="ml-3 flex-1">
                        <div className="flex items-center justify-between">
                            <h3 className={`text-sm font-semibold ${
                                isAchievement ? 'text-yellow-800' : 'text-blue-800'
                            }`}>
                                {isAchievement ? 'Achievement Unlocked!' : 'XP Earned!'}
                            </h3>
                            <button
                                onClick={handleClose}
                                className="text-gray-400 hover:text-gray-600 transition-colors"
                            >
                                <X className="h-4 w-4" />
                            </button>
                        </div>
                        <div className="mt-1">
                            <p className={`text-sm ${
                                isAchievement ? 'text-yellow-700' : 'text-blue-700'
                            }`}>
                                {notification.message}
                            </p>
                            {notification.xp && (
                                <p className="text-xs text-gray-600 mt-1">
                                    +{notification.xp} XP earned
                                </p>
                            )}
                        </div>
                    </div>
                </div>
                
                {/* Progress bar animation */}
                <div className="mt-3">
                    <div className="w-full bg-gray-200 rounded-full h-1">
                        <div 
                            className={`h-1 rounded-full transition-all duration-5000 ease-out ${
                                isAchievement ? 'bg-yellow-400' : 'bg-blue-400'
                            }`}
                            style={{ width: isVisible ? '100%' : '0%' }}
                        ></div>
                    </div>
                </div>
            </div>
        </div>
    )
}

// Hook to manage XP notifications
export function useXPNotifications() {
    const [notification, setNotification] = useState(null)

    const showXPNotification = (xp, message = '') => {
        setNotification({
            type: 'xp',
            xp: xp,
            message: message || `You earned ${xp} XP!`
        })
    }

    const showAchievementNotification = (achievementName, xp) => {
        setNotification({
            type: 'achievement',
            xp: xp,
            message: achievementName
        })
    }

    const clearNotification = () => {
        setNotification(null)
    }

    return {
        notification,
        showXPNotification,
        showAchievementNotification,
        clearNotification
    }
}