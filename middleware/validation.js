const { body, query, param, validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

const sanitize = (fields) => (req, res, next) => {
  for (const field of fields) {
    if (req.body[field] !== undefined) {
      req.body[field] = String(req.body[field]).trim().slice(0, 1000);
    }
  }
  next();
};

const voterLoginValidation = [
  body('code')
    .exists({ checkFalsy: true })
    .withMessage('Voter code is required')
    .isLength({ min: 1, max: 20 })
    .withMessage('Code must be between 1 and 20 characters')
    .matches(/^[A-Za-z0-9]+$/)
    .withMessage('Code must be alphanumeric (case-sensitive)'),
  body('pin')
    .optional()
    .isLength({ min: 4, max: 8 })
    .withMessage('PIN must be 4-8 digits')
    .isNumeric()
    .withMessage('PIN must be numeric'),
  handleValidationErrors,
];

const adminLoginValidation = [
  body('code')
    .exists({ checkFalsy: true })
    .withMessage('Admin code is required')
    .isLength({ min: 1, max: 20 })
    .withMessage('Code must be between 1 and 20 characters')
    .matches(/^[A-Za-z0-9]+$/)
    .withMessage('Code must be alphanumeric (case-sensitive)'),
  body('password')
    .exists({ checkFalsy: true })
    .withMessage('Password is required')
    .isLength({ min: 1, max: 100 })
    .withMessage('Password too long'),
  handleValidationErrors,
];

const admin2faVerifyValidation = [
  body('token')
    .exists({ checkFalsy: true })
    .withMessage('2FA token is required')
    .isLength({ min: 6, max: 6 })
    .withMessage('Token must be 6 digits')
    .isNumeric()
    .withMessage('Token must be numeric'),
  handleValidationErrors,
];

const changePasswordValidation = [
  body('currentPassword').exists({ checkFalsy: true }).withMessage('Current password is required'),
  body('newPassword')
    .exists({ checkFalsy: true })
    .withMessage('New password is required')
    .isLength({ min: 8, max: 100 })
    .withMessage('Password must be 8-100 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  handleValidationErrors,
];

const voterSetPinValidation = [
  body('pin')
    .exists({ checkFalsy: true })
    .withMessage('PIN is required')
    .isLength({ min: 4, max: 8 })
    .withMessage('PIN must be 4-8 digits')
    .isNumeric()
    .withMessage('PIN must be numeric'),
  handleValidationErrors,
];

const forgotPasswordValidation = [
  body('code')
    .exists({ checkFalsy: true })
    .withMessage('Admin code is required')
    .isLength({ min: 1, max: 20 })
    .matches(/^[A-Z0-9]+$/i)
    .withMessage('Invalid code format'),
  handleValidationErrors,
];

const resetPasswordValidation = [
  body('token')
    .exists({ checkFalsy: true })
    .withMessage('Reset token is required')
    .isLength({ min: 64, max: 64 })
    .withMessage('Invalid token'),
  body('password')
    .exists({ checkFalsy: true })
    .withMessage('New password is required')
    .isLength({ min: 8, max: 100 })
    .withMessage('Password must be 8-100 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  handleValidationErrors,
];

const electionValidation = [
  body('name')
    .exists({ checkFalsy: true })
    .withMessage('Election name is required')
    .isLength({ min: 1, max: 200 })
    .withMessage('Name must be 1-200 characters'),
  body('description').optional().isLength({ max: 2000 }).withMessage('Description too long'),
  body('start_date').optional().isISO8601().withMessage('Invalid start date format'),
  body('end_date').optional().isISO8601().withMessage('Invalid end date format'),
  body('primary_color')
    .optional()
    .matches(/^#[0-9A-Fa-f]{6}$/)
    .withMessage('Invalid color format'),
  body('secondary_color')
    .optional()
    .matches(/^#[0-9A-Fa-f]{6}$/)
    .withMessage('Invalid color format'),
  handleValidationErrors,
];

const positionValidation = [
  body('election_id')
    .exists({ checkFalsy: true })
    .withMessage('Election ID is required')
    .isInt({ min: 1 })
    .withMessage('Invalid election ID'),
  body('name')
    .exists({ checkFalsy: true })
    .withMessage('Position name is required')
    .isLength({ min: 1, max: 100 })
    .withMessage('Name must be 1-100 characters'),
  body('description').optional().isLength({ max: 1000 }).withMessage('Description too long'),
  body('sort_order').optional().isInt({ min: 0 }).withMessage('Sort order must be non-negative'),
  handleValidationErrors,
];

const candidateValidation = [
  body('position_id')
    .exists({ checkFalsy: true })
    .withMessage('Position ID is required')
    .isInt({ min: 1 })
    .withMessage('Invalid position ID'),
  body('name')
    .exists({ checkFalsy: true })
    .withMessage('Candidate name is required')
    .isLength({ min: 1, max: 100 })
    .withMessage('Name must be 1-100 characters'),
  body('manifesto').optional().isLength({ max: 5000 }).withMessage('Manifesto too long'),
  body('sort_order').optional().isInt({ min: 0 }).withMessage('Sort order must be non-negative'),
  handleValidationErrors,
];

const castVoteValidation = [
  body('election_id')
    .exists({ checkFalsy: true })
    .withMessage('Election ID is required')
    .isInt({ min: 1 }),
  body('position_id')
    .exists({ checkFalsy: true })
    .withMessage('Position ID is required')
    .isInt({ min: 1 }),
  body('candidate_id')
    .exists({ checkFalsy: true })
    .withMessage('Candidate ID is required')
    .isInt({ min: 1 }),
  body('vote_type').optional().isIn(['yes', 'no']).withMessage('Vote type must be yes or no'),
  handleValidationErrors,
];

const verifyReceiptValidation = [
  body('receipt_hash')
    .exists({ checkFalsy: true })
    .withMessage('Receipt hash is required')
    .isLength({ min: 32, max: 64 })
    .withMessage('Invalid receipt hash'),
  handleValidationErrors,
];

const generateCodesValidation = [
  body('count')
    .exists({ checkFalsy: true })
    .withMessage('Count is required')
    .isInt({ min: 1, max: 1000 })
    .withMessage('Count must be 1-1000'),
  body('election_ids').optional().isArray().withMessage('Election IDs must be an array'),
  handleValidationErrors,
];

const announcementValidation = [
  body('title')
    .exists({ checkFalsy: true })
    .withMessage('Title is required')
    .isLength({ min: 1, max: 200 })
    .withMessage('Title must be 1-200 characters'),
  body('content').optional().isLength({ max: 5000 }).withMessage('Content too long'),
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Priority must be low, medium, or high'),
  body('is_active').optional().isBoolean().withMessage('is_active must be boolean'),
  handleValidationErrors,
];

const idParamValidation = (paramName = 'id') => [
  param(paramName)
    .exists({ checkFalsy: true })
    .withMessage(`${paramName} is required`)
    .isInt({ min: 1 })
    .withMessage(`Invalid ${paramName}`),
  handleValidationErrors,
];

const paginationValidation = [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be 1-100'),
  handleValidationErrors,
];

module.exports = {
  handleValidationErrors,
  sanitize,
  voterLoginValidation,
  adminLoginValidation,
  admin2faVerifyValidation,
  changePasswordValidation,
  voterSetPinValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  electionValidation,
  positionValidation,
  candidateValidation,
  castVoteValidation,
  verifyReceiptValidation,
  generateCodesValidation,
  announcementValidation,
  idParamValidation,
  paginationValidation,
};
