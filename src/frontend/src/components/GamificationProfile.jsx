import { useState, useEffect } from 'react'
import { Star, Trophy, Target, TrendingUp, Award, Users, Upload, Shield } from 'lucide-react'
import axios from 'axios'

export default function GamificationProfile() {
    const [profile, setProfile] = useState(null)
    const [achievements, setAchievements] = useState([])
    const [leaderboard, setLeaderboard] = useState([])
    const [loading, setLoading] = useState(true)
    const [activeTab, setActiveTab] = useState('overview')

    useEffect(() => {
        fetchGamificationData()
    }, [])

    const fetchGamificationData = async () => {
        try {
            const [profileRes, achievementsRes, leaderboardRes] = await Promise.all([
                axios.get('/profile/gamification'),
                axios.get('/achievements'),
                axios.get('/leaderboard')
            ])

            // Transform backend data to match frontend expectations
            const profileData = profileRes.data
            const transformedProfile = {
                level: profileData.xp.level,
                total_xp: profileData.xp.total_xp,
                achievements_count: profileData.achievements.length,
                level_name: getLevelName(profileData.xp.level),
                evidence_uploaded: getEvidenceCount(profileData.achievementProgress),
                weekly_activity: Math.floor(Math.random() * 15), // Mock data for now
                investigations_completed: 0 // Mock data for now
            }

            // Transform achievements data
            const transformedAchievements = [
                ...profileData.achievements.map(achievement => ({
                    ...achievement,
                    earned: true,
                    icon: getAchievementIcon(achievement.achievement_type),
                    badge_color: getAchievementColor(achievement.achievement_type)
                })),
                ...profileData.achievementProgress.map(achievement => ({
                    ...achievement,
                    earned: false,
                    icon: getAchievementIcon(achievement.achievement_type),
                    badge_color: getAchievementColor(achievement.achievement_type),
                    progress_text: `${achievement.current_progress} / ${achievement.target_value}`
                }))
            ]

            setProfile(transformedProfile)
            setAchievements(transformedAchievements)
            setLeaderboard(leaderboardRes.data.leaderboard)
        } catch (error) {
            console.error('Error fetching gamification data:', error)
        } finally {
            setLoading(false)
        }
    }

    // Helper functions for data transformation
    const getLevelName = (level) => {
        const levelNames = {
            1: 'Detective Trainee',
            2: 'Junior Investigator', 
            3: 'Digital Analyst',
            4: 'Senior Detective',
            5: 'Forensic Expert',
            6: 'Investigation Master'
        }
        return levelNames[level] || `Level ${level} Investigator`
    }

    const getEvidenceCount = (achievementProgress) => {
        const uploadAchievement = achievementProgress.find(a => a.achievement_type === 'upload_count' || a.achievement_type === 'first_upload')
        return uploadAchievement ? uploadAchievement.current_progress : 0
    }

    const getAchievementIcon = (achievementType) => {
        const iconMap = {
            'first_upload': 'Upload',
            'upload_count': 'Target', 
            'large_file': 'Shield',
            'total_size': 'Trophy'
        }
        return iconMap[achievementType] || 'Star'
    }

    const getAchievementColor = (achievementType) => {
        const colorMap = {
            'first_upload': 'green',
            'upload_count': 'blue',
            'large_file': 'purple', 
            'total_size': 'orange'
        }
        return colorMap[achievementType] || 'blue'
    }

    const getProgressPercentage = (currentXP, level) => {
        // Backend uses 1000 XP per level, so calculate progress within current level
        const currentLevelBase = (level - 1) * 1000
        const progressInLevel = currentXP - currentLevelBase
        const progressPercentage = (progressInLevel / 1000) * 100
        return Math.min(100, Math.max(0, progressPercentage))
    }

    const getBadgeColor = (color) => {
        const colors = {
            green: 'bg-green-100 text-green-800 border-green-200',
            blue: 'bg-blue-100 text-blue-800 border-blue-200',
            purple: 'bg-purple-100 text-purple-800 border-purple-200',
            yellow: 'bg-yellow-100 text-yellow-800 border-yellow-200',
            orange: 'bg-orange-100 text-orange-800 border-orange-200',
            red: 'bg-red-100 text-red-800 border-red-200'
        }
        return colors[color] || colors.blue
    }

    const getIconComponent = (iconName) => {
        const icons = {
            Upload, Star, Trophy, Award, Users, Shield, Target
        }
        return icons[iconName] || Star
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        )
    }

    return (
        <div className="max-w-6xl mx-auto space-y-6">
            {/* Header with Level and XP */}
            <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl p-6 text-white">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold">{profile?.level_name || 'Detective Trainee'}</h1>
                        <p className="text-blue-100">Level {profile?.level || 1}</p>
                        <div className="flex items-center mt-2 space-x-2">
                            <Star className="h-5 w-5 text-yellow-300" />
                            <span className="font-semibold">{profile?.total_xp || 0} XP</span>
                        </div>
                    </div>
                    <div className="text-right">
                        <div className="bg-white/20 rounded-lg p-4">
                            <TrendingUp className="h-8 w-8 mx-auto mb-2" />
                            <p className="text-sm">Weekly Activity</p>
                            <p className="font-bold">{profile?.weekly_activity || 0}</p>
                        </div>
                    </div>
                </div>

                {/* Progress Bar */}
                <div className="mt-4">
                    <div className="flex justify-between text-sm mb-2">
                        <span>Progress to next level</span>
                        <span>{Math.round(getProgressPercentage(profile?.total_xp || 0, profile?.level || 1))}%</span>
                    </div>
                    <div className="w-full bg-white/20 rounded-full h-2">
                        <div 
                            className="bg-yellow-300 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${getProgressPercentage(profile?.total_xp || 0, profile?.level || 1)}%` }}
                        ></div>
                    </div>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white rounded-lg p-6 shadow-sm border">
                    <div className="flex items-center">
                        <Upload className="h-8 w-8 text-green-600" />
                        <div className="ml-3">
                            <p className="text-sm font-medium text-gray-500">Evidence Uploaded</p>
                            <p className="text-2xl font-semibold text-gray-900">{profile?.evidence_uploaded || 0}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white rounded-lg p-6 shadow-sm border">
                    <div className="flex items-center">
                        <Trophy className="h-8 w-8 text-yellow-600" />
                        <div className="ml-3">
                            <p className="text-sm font-medium text-gray-500">Achievements</p>
                            <p className="text-2xl font-semibold text-gray-900">{profile?.achievements_count || 0}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white rounded-lg p-6 shadow-sm border">
                    <div className="flex items-center">
                        <Target className="h-8 w-8 text-blue-600" />
                        <div className="ml-3">
                            <p className="text-sm font-medium text-gray-500">Investigations</p>
                            <p className="text-2xl font-semibold text-gray-900">{profile?.investigations_completed || 0}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="bg-white rounded-lg shadow-sm border">
                <div className="border-b border-gray-200">
                    <nav className="flex space-x-8 px-6">
                        <button
                            onClick={() => setActiveTab('overview')}
                            className={`py-4 px-1 border-b-2 font-medium text-sm ${
                                activeTab === 'overview'
                                    ? 'border-blue-500 text-blue-600'
                                    : 'border-transparent text-gray-500 hover:text-gray-700'
                            }`}
                        >
                            Overview
                        </button>
                        <button
                            onClick={() => setActiveTab('achievements')}
                            className={`py-4 px-1 border-b-2 font-medium text-sm ${
                                activeTab === 'achievements'
                                    ? 'border-blue-500 text-blue-600'
                                    : 'border-transparent text-gray-500 hover:text-gray-700'
                            }`}
                        >
                            Achievements
                        </button>
                        <button
                            onClick={() => setActiveTab('leaderboard')}
                            className={`py-4 px-1 border-b-2 font-medium text-sm ${
                                activeTab === 'leaderboard'
                                    ? 'border-blue-500 text-blue-600'
                                    : 'border-transparent text-gray-500 hover:text-gray-700'
                            }`}
                        >
                            Leaderboard
                        </button>
                    </nav>
                </div>

                <div className="p-6">
                    {activeTab === 'overview' && (
                        <div className="space-y-4">
                            <h3 className="text-lg font-semibold">Recent Activity</h3>
                            <div className="text-gray-600">
                                Your recent forensic investigation activities and progress will appear here.
                            </div>
                        </div>
                    )}

                    {activeTab === 'achievements' && (
                        <div className="space-y-4">
                            <h3 className="text-lg font-semibold">Achievements</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                {achievements.map((achievement) => {
                                    const IconComponent = getIconComponent(achievement.icon)
                                    return (
                                        <div
                                            key={achievement.id}
                                            className={`p-4 rounded-lg border-2 ${
                                                achievement.earned
                                                    ? getBadgeColor(achievement.badge_color)
                                                    : 'bg-gray-50 text-gray-400 border-gray-200'
                                            }`}
                                        >
                                            <div className="flex items-center space-x-3">
                                                <IconComponent className="h-8 w-8" />
                                                <div className="flex-1">
                                                    <div className="flex items-center justify-between">
                                                        <h4 className="font-semibold">{achievement.name}</h4>
                                                        <span className="text-sm font-medium text-blue-600">
                                                            +{achievement.xp_reward} XP
                                                        </span>
                                                    </div>
                                                    <p className="text-sm">{achievement.description}</p>
                                                    {achievement.earned && achievement.earned_at && (
                                                        <p className="text-xs mt-1 text-green-600">
                                                            ✓ Earned: {new Date(achievement.earned_at).toLocaleDateString()}
                                                        </p>
                                                    )}
                                                    {!achievement.earned && achievement.progress_text && (
                                                        <div className="mt-2">
                                                            <p className="text-xs text-gray-500">
                                                                Progress: {achievement.progress_text}
                                                            </p>
                                                            <div className="w-full bg-gray-200 rounded-full h-1.5 mt-1">
                                                                <div 
                                                                    className="bg-blue-500 h-1.5 rounded-full"
                                                                    style={{ 
                                                                        width: `${Math.min(100, (achievement.current_progress / achievement.target_value) * 100)}%` 
                                                                    }}
                                                                ></div>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )
                                })}
                            </div>
                        </div>
                    )}

                    {activeTab === 'leaderboard' && (
                        <div className="space-y-4">
                            <h3 className="text-lg font-semibold">Top Investigators</h3>
                            <div className="space-y-2">
                                {leaderboard.map((user, index) => (
                                    <div
                                        key={user.id}
                                        className={`flex items-center justify-between p-4 rounded-lg ${
                                            index < 3 ? 'bg-gradient-to-r from-yellow-50 to-yellow-100 border border-yellow-200' : 'bg-gray-50'
                                        }`}
                                    >
                                        <div className="flex items-center space-x-4">
                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center font-bold ${
                                                index === 0 ? 'bg-yellow-500 text-white' :
                                                index === 1 ? 'bg-gray-400 text-white' :
                                                index === 2 ? 'bg-orange-600 text-white' :
                                                'bg-gray-200 text-gray-700'
                                            }`}>
                                                {index + 1}
                                            </span>
                                            <div>
                                                <p className="font-semibold">{user.name} {user.surname}</p>
                                                <p className="text-sm text-gray-500">{user.role} • Level {user.level}</p>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <p className="font-bold text-blue-600">{user.total_xp || 0} XP</p>
                                            <p className="text-sm text-gray-500">{user.achievement_count || 0} achievements</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}