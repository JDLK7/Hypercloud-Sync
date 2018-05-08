--
-- Estructura y datos de la tabla 'users'
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `loginCod` BIGINT,
  `timeValid` BIGINT
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Estructura de la tabla 'files'
--

CREATE TABLE `files` (
	`id` int(11) NOT NULL,
	`path` varchar(255) NOT NULL,
	`size` BIGINT NOT NULL,
	`updated_at` TIMESTAMP NOT NULL,
	`access` int(3) NOT NULL,
	`user_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- -- --------------------------------------------------------
--

--
-- Claves y restricciones de la tabla 'users'
--

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);
  
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- Claves y restricciones de la tabla 'files'
--

ALTER TABLE `files`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `path` (`path`);

ALTER TABLE `files`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

ALTER TABLE `files`
  ADD FOREIGN KEY (`user_id`) REFERENCES `users`(`id`); 

ALTER TABLE files MODIFY id varchar(50) NOT NULL;

ALTER TABLE files MODIFY access int(3);