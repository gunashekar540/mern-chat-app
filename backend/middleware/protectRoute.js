import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';

const protectRoute = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;

        if (!token) {
            // Return after sending response to prevent further code execution
            return res.status(401).json({ error: "Unauthorized - No Token Provided" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded) {
            // Return after sending response to prevent further code execution
            return res.status(401).json({ error: "Unauthorized - Invalid Token" });
        }

        const user = await User.findById(decoded.userId).select("-password");

        if (!user) {
            // Return after sending response to prevent further code execution
            return res.status(404).json({ error: "User Not Found" });
        }

        req.user = user;
        next(); // Continue to the next middleware or route handler

    } catch (error) {
        console.log("Error in protectRoute middleware:", error.message);
        // Return after sending response to prevent further code execution
        return res.status(500).json({ error: "Internal Server Error" });
    }
};

export default protectRoute;
