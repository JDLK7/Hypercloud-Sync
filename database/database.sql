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
	`id` varchar(50) NOT NULL,
	`path` varchar(255) NOT NULL,
	`size` BIGINT NOT NULL,
	`updated_at` TIMESTAMP NOT NULL,
	`access` int(3),
	`user_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `versions` (
	`file_id` varchar(50) NOT NULL,
	`version_id` varchar(50) NOT NULL
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
  ADD FOREIGN KEY (`user_id`) REFERENCES `users`(`id`);

--
-- Claves y restricciones de la tabla 'versions'
--

ALTER TABLE `versions`
  ADD PRIMARY KEY (`file_id`, `version_id`),
  ADD FOREIGN KEY (`file_id`) REFERENCES `files`(`id`),
  ADD FOREIGN KEY (`version_id`) REFERENCES `files`(`id`);