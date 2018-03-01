--
-- Estructura y datos de tabla 'users'
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email` varchar(50) NOT NULL,
  `name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

INSERT INTO `users` (`email`, `name`) VALUES
(1, 'josesguay@gmail.com', 'Jose Domenech Leal'),
(2, 'joaquin.anton95@gmail.com', 'Joaquin Jose Anton Orts');

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);
  
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;