/*-
 * Copyright (c) 2018-2019 The FreeBSD Foundation
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Portions of this software were developed by
 * Konstantin Belousov <kib@FreeBSD.org> under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/asm_linkage.h>

/*
 * From FreeBSD, most recent update to this code is:
 *
 * commit f1be262ec11c1c35e6485f432415b5b52adb505d
 * Author: Mateusz Guzik <mjg@FreeBSD.org>
 * Date:   Sun Jan 31 16:46:18 2021 +0100
 *
 *     amd64: move memcmp checks upfront
 *
 * Adapted to illumos by reworking macros.
 */

/*
 * memcmp(b1, b2, len)
 *	   rdi,rsi,rdx
 */
	ENTRY(memcmp)
	pushq	%rbp
	movq	%rsp, %rbp

	xorl	%eax,%eax
	cmpq	%rdi,%rsi
	je	100000f
10:
	cmpq	$16,%rdx
	ja	101632f

	cmpb	$8,%dl
	jg	100816f

	cmpb	$4,%dl
	jg	100408f

	cmpb	$2,%dl
	jge	100204f

	cmpb	$1,%dl
	jl	100000f
	movzbl	(%rdi),%eax
	movzbl	(%rsi),%r8d
	subl	%r8d,%eax
100000:
	popq	%rbp
	ret

	.p2align 4,0x90
100816:
	movq	(%rdi),%r8
	movq	(%rsi),%r9
	cmpq	%r8,%r9
	jne	90f
	movq	-8(%rdi,%rdx),%r8
	movq	-8(%rsi,%rdx),%r9
	cmpq	%r8,%r9
	jne	90f
	popq	%rbp
	ret
	.p2align 4,0x90
100408:
	movl	(%rdi),%r8d
	movl	(%rsi),%r9d
	cmpl	%r8d,%r9d
	jne	90f
	movl	-4(%rdi,%rdx),%r8d
	movl	-4(%rsi,%rdx),%r9d
	cmpl	%r8d,%r9d
	jne	90f
	popq	%rbp
	ret
	.p2align 4,0x90
100204:
	movzwl	(%rdi),%r8d
	movzwl	(%rsi),%r9d
	cmpl	%r8d,%r9d
	jne	90f
	movzwl	-2(%rdi,%rdx),%r8d
	movzwl	-2(%rsi,%rdx),%r9d
	cmpl	%r8d,%r9d
	jne	90f
	popq	%rbp
	ret
	.p2align 4,0x90
101632:
	cmpq	$32,%rdx
	ja	103200f
	movq	(%rdi),%r8
	movq	(%rsi),%r9
	cmpq	%r8,%r9
	jne	90f
	movq	8(%rdi),%r8
	movq	8(%rsi),%r9
	cmpq	%r8,%r9
	jne	90f
	movq	-16(%rdi,%rdx),%r8
	movq	-16(%rsi,%rdx),%r9
	cmpq	%r8,%r9
	jne	90f
	movq	-8(%rdi,%rdx),%r8
	movq	-8(%rsi,%rdx),%r9
	cmpq	%r8,%r9
	jne	90f
	popq	%rbp
	ret
	.p2align 4,0x90
103200:
	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	subq	(%rsi),%r8
	subq	8(%rsi),%r9
	orq	%r8,%r9
	jnz	10320000f

	movq    16(%rdi),%r8
	movq    24(%rdi),%r9
	subq    16(%rsi),%r8
	subq    24(%rsi),%r9
	orq	%r8,%r9
	jnz     10320016f

	leaq	32(%rdi),%rdi
	leaq	32(%rsi),%rsi
	subq	$32,%rdx
	cmpq	$32,%rdx
	jae	103200b
	cmpb	$0,%dl
	jne	10b
	popq	%rbp
	ret

/*
 * Mismatch was found in a 16 byte block, the sub/or above destroyed
 * the loaded values. Load the two quads again (all within the block,
 * which is within the buffers) and compute the result from them.
 */
	.p2align 4,0x90
10320016:
	leaq	16(%rdi),%rdi
	leaq	16(%rsi),%rsi
10320000:
	movq	(%rdi),%r8
	movq	(%rsi),%r9
	cmpq	%r8,%r9
	jne	90f
	movq	8(%rdi),%r8
	movq	8(%rsi),%r9

/*
 * %r8 and %r9 hold the (zero-extended, little-endian) words from b1 and
 * b2. All bytes preceding them have compared equal; the first differing
 * byte is the lowest one set in %r8 ^ %r9. If the words are equal
 * (the buffers changed under us), report equality.
 */
90:
	movq	%r8,%rcx
	xorq	%r9,%rcx
	jz	91f
	bsfq	%rcx,%rcx
	andl	$0x38,%ecx
	shrq	%cl,%r8
	shrq	%cl,%r9
	movzbl	%r8b,%eax
	movzbl	%r9b,%r8d
	subl	%r8d,%eax
91:
	popq	%rbp
	ret
	SET_SIZE(memcmp)
