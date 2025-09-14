// Example integration of XP notifications with file upload
// This shows how to integrate the XP system with the existing WorkspaceDetail component

import { useState } from 'react'
import XPNotification, { useXPNotifications } from './XPNotification'
import toast from 'react-hot-toast'

export default function WorkspaceDetailWithXP() {
    const [uploading, setUploading] = useState(false)
    const [uploadData, setUploadData] = useState({
        file: null,
        description: '',
        tags: ''
    })
    
    const { notification, showXPNotification, showAchievementNotification, clearNotification } = useXPNotifications()

    const handleFileUpload = async (e) => {
        e.preventDefault()
        
        if (!uploadData.file) {
            toast.error('Please select a file to upload')
            return
        }
        setUploading(true)
        
        const formData = new FormData()
        formData.append('file', uploadData.file)
        formData.append('description', uploadData.description)
        formData.append('tags', uploadData.tags)
        
        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}/evidence`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: formData
            })
            
            if (response.ok) {
                const result = await response.json()
                toast.success('Evidence uploaded successfully!')
                
                // Handle XP notifications from backend response
                if (result.xp && result.xp.xpAwarded) {
                    showXPNotification(result.xp.xpAwarded, `File uploaded: ${result.filename}`)
                }
                
                // Handle achievement notifications
                if (result.newAchievements && result.newAchievements.length > 0) {
                    // Show the first achievement (you could queue multiple)
                    const achievement = result.newAchievements[0]
                    showAchievementNotification(achievement.name, achievement.xp_reward)
                    
                    // If multiple achievements, you could show them sequentially
                    if (result.newAchievements.length > 1) {
                        setTimeout(() => {
                            for (let i = 1; i < result.newAchievements.length; i++) {
                                const ach = result.newAchievements[i]
                                setTimeout(() => {
                                    showAchievementNotification(ach.name, ach.xp_reward)
                                }, i * 3000) // 3 second delay between achievements
                            }
                        }, 5000)
                    }
                }
                
                // Reset form
                setUploadData({ file: null, description: '', tags: '' })
                // You would call fetchEvidence() here to refresh the list
            } else {
                const errorData = await response.json()
                toast.error(errorData.error || 'Upload failed')
            }
        } catch (error) {
            console.error('Upload error:', error)
            toast.error('Upload failed')
        } finally {
            setUploading(false)
        }
    }

    return (
        <div>
            {/* Your existing workspace detail component JSX here */}
            
            {/* XP Notification Component */}
            <XPNotification 
                notification={notification} 
                onClose={clearNotification} 
            />
            
            {/* Upload form example */}
            <form onSubmit={handleFileUpload} className="space-y-4">
                <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-2">
                        Evidence File *
                    </label>
                    <input
                        type="file"
                        onChange={(e) => setUploadData({...uploadData, file: e.target.files[0]})}
                        className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        required
                    />
                </div>
                
                <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-2">
                        Description
                    </label>
                    <textarea
                        value={uploadData.description}
                        onChange={(e) => setUploadData({...uploadData, description: e.target.value})}
                        className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        rows="3"
                        placeholder="Describe this evidence..."
                    />
                </div>
                
                <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-2">
                        Tags
                    </label>
                    <input
                        type="text"
                        value={uploadData.tags}
                        onChange={(e) => setUploadData({...uploadData, tags: e.target.value})}
                        className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="forensic, evidence, case1..."
                    />
                </div>
                
                <button
                    type="submit"
                    disabled={uploading}
                    className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-semibold transition-colors"
                >
                    {uploading ? 'Uploading...' : 'Upload Evidence'}
                </button>
            </form>
        </div>
    )
}

/*
INTEGRATION INSTRUCTIONS:

1. Import the XP notification components in your existing WorkspaceDetail component:
   ```jsx
   import XPNotification, { useXPNotifications } from './XPNotification'
   ```

2. Add the useXPNotifications hook to your component:
   ```jsx
   const { notification, showXPNotification, showAchievementNotification, clearNotification } = useXPNotifications()
   ```

3. Update your handleFileUpload function to handle the XP response from the backend
   (see example above)

4. Add the XP notification component to your JSX:
   ```jsx
   <XPNotification 
       notification={notification} 
       onClose={clearNotification} 
   />
   ```

The backend now returns XP and achievement data in this format:
{
    "message": "Evidence uploaded successfully",
    "evidenceId": 123,
    "filename": "document.pdf", 
    "fileHash": "abc123...",
    "size": 1024,
    "xp": {
        "xpAwarded": 15,
        "newTotal": 145,
        "newLevel": 1
    },
    "newAchievements": [
        {
            "id": 1,
            "name": "First Upload",
            "description": "Upload your first piece of evidence",
            "xp_reward": 50
        }
    ]
}
*/