package br.com.cadastroit.services.utils;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.text.NumberFormat;
import java.util.Locale;

public class BigDecimalUtils {

	public static final BigDecimal CEM = BigDecimal.TEN.multiply(BigDecimal.TEN);
	public static final BigDecimal DOIS = new BigDecimal("2");
	public static final int SCALE_MONEY = 2;
	public static final int SCALE = 10;

	public static BigDecimal parseToBigDecimal(double valor) {

		if (Double.isNaN(valor)) {
			return BigDecimal.ZERO;
		}
		return BigDecimal.valueOf(valor);
	}

	public static BigDecimal getZeroIfNull(BigDecimal value) {
		return value == null ? BigDecimal.ZERO : value;
	}

	public static BigDecimal zeroIfNull(BigDecimal value) {

		return value == null ? BigDecimal.ZERO : value;
	}

	public static boolean isGreaterThanZero(BigDecimal valor) {

		return isGreaterThan(valor, BigDecimal.ZERO);
	}

	public static boolean isGreaterOrEqualThanZero(BigDecimal valor) {

		return isGreaterOrEqualThan(valor, BigDecimal.ZERO);
	}

	public static boolean isGreaterOrEqualThan(BigDecimal valor, BigDecimal comparacao) {

		return isGreaterThan(valor, comparacao) || isEqual(valor, comparacao);
	}

	public static boolean isGreaterThan(BigDecimal valor, BigDecimal comparacao) {

		int resultadoComparacao = comparacao(valor, comparacao);
		return resultadoComparacao == 1;
	}

	public static boolean isLessThanZero(BigDecimal valor) {

		return isLessThan(valor, BigDecimal.ZERO);
	}

	public static boolean isLessOrEqualThanZero(BigDecimal valor) {

		return isLessOrEqualThan(valor, BigDecimal.ZERO);
	}

	public static boolean isLessOrEqualThan(BigDecimal valor, BigDecimal comparacao) {

		return isLessThan(valor, comparacao) || isEqual(valor, comparacao);
	}

	public static boolean isLessThan(BigDecimal valor, BigDecimal comparadao) {

		return comparacao(valor, comparadao) == -1;
	}

	public static BigDecimal parseToBigDecimalOrZero(Object value) {

		if (value == null)
			return BigDecimal.ZERO;

		return (BigDecimal) value;
	}

	public static boolean isZero(BigDecimal valor) {

		return isEqual(valor, BigDecimal.ZERO);
	}

	public static boolean isNotZero(BigDecimal valor) {

		return !isZero(valor);
	}

	public static boolean isEqual(BigDecimal a, BigDecimal b) {

		return comparacao(a, b) == 0;
	}

	public static boolean isNotEqual(BigDecimal a, BigDecimal b) {

		return !isEqual(a, b);
	}

	public static BigDecimal calcularProporcional(BigDecimal referencia, BigDecimal subtotal, BigDecimal total) {

		return calcularProporcional(referencia, subtotal, total, SCALE_MONEY);
	}

	public static BigDecimal calcularProporcional(BigDecimal referencia, BigDecimal subtotal, BigDecimal total, int casasDecimais) {

		if (BigDecimalUtils.isZero(total))
			return BigDecimal.ZERO;

		referencia = BigDecimalUtils.zeroIfNull(referencia);
		subtotal = BigDecimalUtils.zeroIfNull(subtotal);

		BigDecimal parcial = referencia.multiply(subtotal);

		return divide(parcial, total, casasDecimais);
	}

	public static BigDecimal divide(BigDecimal a, BigDecimal b) {

		return divide(a, b, SCALE_MONEY);
	}

	public static BigDecimal divide(BigDecimal a, BigDecimal b, int scale) {

		a = zeroIfNull(a);
		b = isZero(b) ? BigDecimal.ONE : b;

		return a.divide(b, scale, RoundingMode.HALF_EVEN);
	}

	public static BigDecimal divide10casas(BigDecimal dividendo, BigDecimal divisor) {

		return dividendo.divide(divisor, 10, RoundingMode.HALF_EVEN);
	}

	public static BigDecimal arredondar(BigDecimal value) {

		return arredondar(value, SCALE_MONEY);
	}

	public static BigDecimal arredondar(BigDecimal value, int scale) {

		return arredondar(value, scale, RoundingMode.HALF_EVEN);
	}

	public static BigDecimal arredondar(BigDecimal value, RoundingMode roundingMode) {

		return arredondar(value, SCALE_MONEY, roundingMode);
	}

	public static BigDecimal arredondar(BigDecimal value, int scale, RoundingMode roundingMode) {

		if (value == null)
			return null;

		return value.setScale(scale, roundingMode);
	}

	/**
	 * M�todo duplicado de arrendondar mas utilizando RoudingMode.DOWN. Utilizar m�todo {@link #arredondar() arredondar}
	 */
	@Deprecated
	public static BigDecimal truncar(BigDecimal value) {

		return truncar(value, SCALE_MONEY);
	}

	/**
	 * M�todo duplicado de arrendondar mas utilizando RoudingMode.DOWN. Utilizar m�todo {@link #arredondar() arredondar}
	 */
	@Deprecated
	public static BigDecimal truncar(BigDecimal value, int scale) {

		return arredondar(value, scale, RoundingMode.DOWN);
	}

	
	private static int comparacao(BigDecimal valor, BigDecimal comparacao) {

		valor = zeroIfNull(valor);

		if (comparacao == null)
			comparacao = BigDecimal.ZERO;

		int resultado = valor.compareTo(comparacao);

		return resultado;
	}

	private static Field getField(Class<? extends Object> classe, String nomeAtributo) throws NoSuchFieldException {

		Field campo = classe.getDeclaredField(nomeAtributo);
		campo.setAccessible(true);

		return campo;
	}

	public static BigDecimal getValueByPercentage(BigDecimal value, BigDecimal percentage) {

		BigDecimal porcentagemCalculada = dividePorCem(percentage);
		return value.multiply(porcentagemCalculada);
	}

	public static BigDecimal getPercentageByValue(BigDecimal value, BigDecimal valueReference) {

		BigDecimal valorCalculado = divide(value, valueReference, SCALE);
		return valorCalculado.multiply(CEM);
	}

	public static BigDecimal dividePorCem(BigDecimal dividendo) {

		return divide(dividendo, CEM, 4);
	}

	public static boolean isGreaterOrEqual(BigDecimal valor, BigDecimal comparacao) {

		int resultadoComparacao = comparacao(valor, comparacao);
		return resultadoComparacao == 1 || resultadoComparacao == 0;
	}

	public static BigDecimal regra3(BigDecimal valor1, BigDecimal valor2, BigDecimal porcentagem) {

		if (BigDecimalUtils.isGreaterThanZero(porcentagem)) {
			BigDecimal regra3 = (valor1.multiply(valor2)).divide(porcentagem, 6, RoundingMode.HALF_EVEN);

			return arredondar(regra3, 6);
		} else {
			return BigDecimal.ZERO;
		}

	}

	public static String formatarValorMonetario(BigDecimal valor) {

		return formatarValorMonetario(valor, false);
	}

	public static String formatarValorMonetario(BigDecimal valor, int casasDecimais) {

		return formatarValorMonetario(valor, false, casasDecimais);
	}

	public static String formatarValorMonetario(BigDecimal valor, boolean usaSeparadorMilhar) {

		return formatarValorMonetario(valor, usaSeparadorMilhar, SCALE_MONEY);
	}

	public static String formatarValorMonetario(BigDecimal valor, boolean usaSeparadorMilhar, int casasDecimais) {

		if (valor == null)
			return "";

		NumberFormat nf = NumberFormat.getNumberInstance(new Locale("pt", "BR"));
		nf.setMinimumFractionDigits(casasDecimais);
		nf.setGroupingUsed(usaSeparadorMilhar);
		BigDecimal result = valor.setScale(casasDecimais, RoundingMode.HALF_DOWN);

		return nf.format(result);
	}

	/**
	 * Utilizar o m�todo formatarValorMonetario()
	 */
	@Deprecated
	public static String toString(BigDecimal valor) {

		return toString(valor, false);
	}

	/**
	 * Utilizar o m�todo formatarValorMonetario()
	 */
	@Deprecated
	public static String toString(BigDecimal valor, boolean usaSeparadorMilhar) {

		return toString(valor, usaSeparadorMilhar, SCALE_MONEY);
	}

	/**
	 * Utilizar o m�todo formatarValorMonetario()
	 */
	@Deprecated
	public static String toString(BigDecimal valor, boolean usaSeparadorMilhar, int casasDecimais) {

		if (valor == null)
			return null;

		NumberFormat nf = NumberFormat.getNumberInstance(new Locale("pt", "BR"));
		nf.setMinimumFractionDigits(casasDecimais);
		nf.setGroupingUsed(usaSeparadorMilhar);
		BigDecimal result = valor.setScale(casasDecimais, RoundingMode.HALF_DOWN);

		return nf.format(result);
	}

	public static BigDecimal porcentagem(BigDecimal valor, BigDecimal porcentagem) {

		BigDecimal porcentagemCalculada = dividePorCem(porcentagem);
		return zeroIfNull(valor).multiply(porcentagemCalculada);
	}

	public static BigDecimal average(BigDecimal value, BigDecimal value2) {

		if (value == null || value2 == null)
			return BigDecimal.ZERO;

		return divide(value.add(value2), DOIS);
	}

	public static BigDecimal zeroIfNegative(BigDecimal value) {

		if (isLessThanZero(value))
			return BigDecimal.ZERO;

		return value;
	}

}