INSERT INTO elections (id, name, description, status, start_date, end_date, logo_url, primary_color, secondary_color, results_published, created_at) VALUES
(1, 'BISECO Prefectorial Election', 'School prefect election at Bisease Senior High School', 'active', NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), '/images/placeholder.png', '#0044cc', '#0066cc', 0, NOW()),
(2, 'Class Representative Election', 'Election for class representatives', 'upcoming', DATE_ADD(NOW(), INTERVAL 45 DAY), DATE_ADD(NOW(), INTERVAL 60 DAY), '/images/placeholder.png', '#0066cc', '#0099ff', 0, NOW());

INSERT INTO positions (id, election_id, name, description, sort_order, created_at) VALUES
(1, 1, 'School Captain', 'Head of school government', 0, NOW()),
(2, 1, 'Deputy Captain', 'Deputy to School Captain', 1, NOW()),
(3, 1, 'Games Prefect', 'School games and sports representative', 2, NOW()),
(4, 1, 'Social Prefect', 'School social events coordinator', 3, NOW()),
(5, 2, 'Class Representative', 'Represents class in school matters', 0, NOW());

INSERT INTO candidates (id, position_id, name, photo, manifesto, sort_order, created_at) VALUES
(1, 1, 'John Doe', '/images/placeholder.png', 'I will focus on improving school facilities and student welfare.', 0, NOW()),
(2, 1, 'Jane Smith', '/images/placeholder.png', 'My platform is about academic excellence and discipline.', 1, NOW()),
(3, 2, 'Mike Brown', '/images/placeholder.png', 'Dedicated to representing our class voice.', 0, NOW()),
(4, 3, 'Sarah Wilson', '/images/placeholder.png', 'Passionate about sports and student activities.', 0, NOW()),
(5, 5, 'Emily Davis', '/images/placeholder.png', 'Representing our class with integrity.', 0, NOW());