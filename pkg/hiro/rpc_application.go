/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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

package hiro

import (
	"context"

	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/golang/protobuf/ptypes/empty"
)

// ApplicationCreate implements the pb.HiroServer interface
func (s *RPCServer) ApplicationCreate(ctx context.Context, params *pb.ApplicationCreateRequest) (*pb.Application, error) {
	return nil, nil
}

// ApplicationUpdate implements the pb.HiroServer interface
func (s *RPCServer) ApplicationUpdate(ctx context.Context, params *pb.ApplicationUpdateRequest) (*pb.Application, error) {
	return nil, nil
}

// ApplicationGet implements the pb.HiroServer interface
func (s *RPCServer) ApplicationGet(ctx context.Context, params *pb.ApplicationGetRequest) (*pb.Application, error) {
	return nil, nil
}

// ApplicationList implements the pb.HiroServer interface
func (s *RPCServer) ApplicationList(req *pb.ApplicationListRequest, stream pb.Hiro_ApplicationListServer) error {
	return nil
}

// ApplicationDelete implements the pb.HiroServer interface
func (s *RPCServer) ApplicationDelete(ctx context.Context, params *pb.ApplicationDeleteRequest) (*empty.Empty, error) {
	return nil, nil
}
