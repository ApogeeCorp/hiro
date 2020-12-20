/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://github.com/ModelRocket/hiro
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package oauth

type (
	// Notification is a simply a notification interface
	Notification interface {
		Type() NotificationType
		Subject() string
		Channels() []NotificationChannel
		URI() *URI
	}

	// NotificationType is a notification type
	NotificationType string

	// NotificationChannel is the channel to notify
	NotificationChannel string
)

const (
	// NotificationTypeVerify are verification notifications
	NotificationTypeVerify NotificationType = "verify"

	// NotificationTypePassword are password notification
	NotificationTypePassword NotificationType = "password"

	// NotificationTypeInvite are invitation notification
	NotificationTypeInvite NotificationType = "invite"

	// NotificationChannelEmail is an email notification
	NotificationChannelEmail NotificationChannel = "email"

	// NotificationChannelPhone is an sms notification
	NotificationChannelPhone NotificationChannel = "phone"
)
