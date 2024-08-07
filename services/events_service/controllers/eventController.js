import Event from '../models/Event.js';
import uploadToS3 from '../../../utils/fileUpload.js';
import User from '../../auth_service/models/user.model.js';

export const createEvent = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (user.userType !== 1) {
      return res.status(403).json({ message: 'You must be an event creator to perform this action' });
    }

    const { date, venue, guest, description, price } = req.body;
    
    // Validate required fields
    if (!date || !venue || !guest || !description || !price || !req.file) {
      return res.status(400).json({ message: 'All fields including poster are required' });
    }

    const posterUrl = await uploadToS3(req.file);

    const event = new Event({
      poster: posterUrl,
      date: new Date(date),
      venue,
      guest,
      description,
      price: parseFloat(price),
      createdBy: userId
    });

    await event.save();
    res.status(201).json(event);
  } catch (error) {
    console.error('Error in createEvent:', error);
    res.status(500).json({ error: 'An error occurred while creating the event' });
  }
};

export const getAllEvents = async (req, res) => {
  try {
    const events = await Event.find().sort('-date');
    res.json(events);
  } catch (error) {
    console.error('Error in getAllEvents:', error);
    res.status(500).json({ error: 'An error occurred while fetching events' });
  }
};

export const getEventById = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }
    res.json(event);
  } catch (error) {
    console.error('Error in getEventById:', error);
    res.status(500).json({ error: 'An error occurred while fetching the event' });
  }
};