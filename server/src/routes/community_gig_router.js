const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');

/**
 * Community Gig Router
 * Handles sharing tasks with rewards and automatic completion tracking
 * 
 * @param {Object} pool - MySQL connection pool
 * @param {Function} authenticateToken - JWT authentication middleware
 * @param {Function} sendToUser - Notification function
 * @returns {express.Router} Configured router
 */
function createCommunityGigRouter(pool, authenticateToken, sendToUser) {
    const router = express.Router();

    /**
     * GET /community/gig/:taskId/action
     * Display the share page with task details and reward information
     */
    router.get('/gig/:taskId/action', async (req, res) => {
        const { taskId } = req.params;

        try {
            // Fetch task details from database
            const [taskRows] = await pool.query(
                'SELECT id, `desc`, type, shortResponse, reward, image FROM tasks WHERE id = ?',
                [taskId]
            );

            if (taskRows.length === 0) {
                return res.status(404).json({ 
                    error: 'Task not found',
                    message: 'The requested task does not exist' 
                });
            }

            const task = taskRows[0];

            // Extract link from task description if present
            const linkMatch = task.desc ? task.desc.match(/https?:\/\/[^\s]+/i) : null;
            const shareLink = linkMatch ? linkMatch[0] : null;

            // Return task information for the share page
            res.json({
                success: true,
                task: {
                    id: task.id,
                    description: task.desc,
                    type: task.type,
                    reward: task.reward,
                    image: task.image,
                    shareLink: shareLink,
                    shortResponse: task.shortResponse
                },
                message: shareLink 
                    ? `Complete this task and earn ${task.reward} tokens!` 
                    : 'No share link available for this task'
            });

        } catch (error) {
            console.error('Error fetching task:', error.message);
            res.status(500).json({ 
                error: 'Failed to fetch task details',
                message: error.message 
            });
        }
    });

    /**
     * POST /community/gig/:taskId/share
     * Process the share action, verify login, mark task complete, and reward user
     * Requires JWT authentication
     */
    router.post('/gig/:taskId/share', authenticateToken, async (req, res) => {
        const { taskId } = req.params;
        const userEmail = req.user.email; // From JWT token

        try {
            // Fetch task details
            const [taskRows] = await pool.query(
                'SELECT id, `desc`, type, reward, image FROM tasks WHERE id = ?',
                [taskId]
            );

            if (taskRows.length === 0) {
                return res.status(404).json({ 
                    error: 'Task not found',
                    message: 'The requested task does not exist' 
                });
            }

            const task = taskRows[0];

            // Check if user has already completed this task
            const [existingAnswers] = await pool.query(
                'SELECT id, status FROM answers WHERE email = ? AND taskId = ?',
                [userEmail, taskId]
            );

            if (existingAnswers.length > 0 && existingAnswers[0].status === 'approved') {
                return res.status(400).json({ 
                    error: 'Task already completed',
                    message: 'You have already completed this task and received the reward'
                });
            }

            // Extract share link from description
            const linkMatch = task.desc ? task.desc.match(/https?:\/\/[^\s]+/i) : null;
            const shareLink = linkMatch ? linkMatch[0] : null;

            if (!shareLink) {
                return res.status(400).json({ 
                    error: 'No share link available',
                    message: 'This task does not have a shareable link' 
                });
            }

            // Generate unique answer ID
            const answerId = `ANS-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

            // Record the task completion
            await pool.query(
                `INSERT INTO answers (id, email, taskId, type, response, reward, reviewed, status) 
                 VALUES (?, ?, ?, ?, ?, ?, 1, 'approved')`,
                [
                    answerId,
                    userEmail,
                    taskId,
                    task.type || 'share',
                    `Shared link: ${shareLink}`,
                    task.reward
                ]
            );

            // Get current user points
            const [userRows] = await pool.query(
                'SELECT verifiedPoints FROM users WHERE email = ?',
                [userEmail]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ 
                    error: 'User not found',
                    message: 'User account does not exist' 
                });
            }

            const currentBalance = parseFloat(userRows[0].verifiedPoints) || 0;
            const newBalance = currentBalance + parseFloat(task.reward);

            // Update user verifiedPoints and record count
            await pool.query(
                'UPDATE users SET verifiedPoints = ?, record = record + 1 WHERE email = ?',
                [newBalance, userEmail]
            );

            // Send notification to user
            try {
                await sendToUser(
                    userEmail,
                    'Task Completed! 🎉',
                    `You've earned ${task.reward} tokens for completing the share task!`,
                    {
                        taskId: taskId,
                        reward: task.reward,
                        newBalance: newBalance
                    }
                );
            } catch (notifError) {
                console.error('Notification error:', notifError.message);
                // Continue even if notification fails
            }

            // Return success response
            res.json({
                success: true,
                message: 'Task completed successfully!',
                data: {
                    answerId: answerId,
                    taskId: taskId,
                    reward: task.reward,
                    previousBalance: currentBalance,
                    newBalance: newBalance,
                    shareLink: shareLink
                }
            });

        } catch (error) {
            console.error('Error processing share:', error.message);
            res.status(500).json({ 
                error: 'Failed to process share',
                message: error.message 
            });
        }
    });

    /**
     * GET /community/gig/:taskId/status
     * Check if user has completed this task
     * Requires JWT authentication
     */
    router.get('/gig/:taskId/status', authenticateToken, async (req, res) => {
        const { taskId } = req.params;
        const userEmail = req.user.email;

        try {
            const [answers] = await pool.query(
                'SELECT id, status, reward, response FROM answers WHERE email = ? AND taskId = ?',
                [userEmail, taskId]
            );

            const completed = answers.length > 0 && answers[0].status === 'approved';

            res.json({
                success: true,
                completed: completed,
                answer: completed ? answers[0] : null
            });

        } catch (error) {
            console.error('Error checking task status:', error.message);
            res.status(500).json({ 
                error: 'Failed to check task status',
                message: error.message 
            });
        }
    });

    /**
     * GET /community/gig/tasks
     * Get all available share tasks
     */
    router.get('/gig/tasks', async (req, res) => {
        try {
            const [tasks] = await pool.query(
                'SELECT id, `desc`, type, reward, image FROM tasks WHERE type = ? OR `desc` LIKE ?',
                ['share', '%http%']
            );

            res.json({
                success: true,
                tasks: tasks.map(task => ({
                    id: task.id,
                    description: task.desc,
                    type: task.type,
                    reward: task.reward,
                    image: task.image,
                    hasLink: task.desc ? /https?:\/\/[^\s]+/i.test(task.desc) : false
                }))
            });

        } catch (error) {
            console.error('Error fetching tasks:', error.message);
            res.status(500).json({ 
                error: 'Failed to fetch tasks',
                message: error.message 
            });
        }
    });

    return router;
}

module.exports = { createCommunityGigRouter };
