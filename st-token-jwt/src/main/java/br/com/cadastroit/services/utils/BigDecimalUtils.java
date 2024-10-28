package br.com.cadastroit.services.utils;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.text.NumberFormat;
import java.util.List;
import java.util.Locale;

public class BigDecimalUtils {

	public static final BigDecimal CEM = BigDecimal.TEN.multiply(BigDecimal.TEN);
	public static final BigDecimal DOIS = new BigDecimal("2");
	public static final int SCALE_MONEY = 2;
	public static final int SCALE = 10;

	public static BigDecimal getZeroIfNull(BigDecimal value) {
		return value == null ? BigDecimal.ZERO : value;
	}
	
	public static BigDecimal parseToBigDecimal(String value) throws Exception {

		try {
			return new BigDecimal(value);
		} catch (NumberFormatException e) {
			throw new Exception("exception.illegal.argument.number.format");
		}
	}

	public static BigDecimal parseToBigDecimal(double valor) {

		if (Double.isNaN(valor)) {
			return BigDecimal.ZERO;
		}
		return BigDecimal.valueOf(valor);
	}

	public static BigDecimal zeroIfNull(String value) {

		return StringUtils.isBlank(value) ? BigDecimal.ZERO : new BigDecimal(value);
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

	public static boolean isLessOrEqualThanZero(BigDecimal valor) {

		return isLessOrEqualThan(valor, BigDecimal.ZERO);
	}
	
	public static BigDecimal zeroIfNegative(BigDecimal value) {

		if (isLessThanZero(value))
			return BigDecimal.ZERO;

		return value;
	}
	
	public static boolean isLessThanZero(BigDecimal valor) {

		return isLessThan(valor, BigDecimal.ZERO);
	}
	
	public static boolean isLessOrEqualThan(BigDecimal valor, BigDecimal comparacao) {

		return isLessThan(valor, comparacao) || isEqual(valor, comparacao);
	}

	public static boolean isLessThan(BigDecimal valor, BigDecimal comparadao) {

		return comparacao(valor, comparadao) == -1;
	}

	private static int comparacao(BigDecimal valor, BigDecimal comparacao) {

		valor = zeroIfNull(valor);

		if (comparacao == null)
			comparacao = BigDecimal.ZERO;

		int resultado = valor.compareTo(comparacao);

		return resultado;
	}

	public static BigDecimal parseToBigDecimalOrZero(String value) throws Exception {

		if (StringUtils.isBlank(value))
			return BigDecimal.ZERO;

		return parseToBigDecimal(value);
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
	 * Método duplicado de arrendondar mas utilizando RoudingMode.DOWN. Utilizar método {@link #arredondar() arredondar}
	 */
	@Deprecated
	public static BigDecimal truncar(BigDecimal value) {

		return truncar(value, SCALE_MONEY);
	}

	/**
	 * Método duplicado de arrendondar mas utilizando RoudingMode.DOWN. Utilizar método {@link #arredondar() arredondar}
	 */
	@Deprecated
	public static BigDecimal truncar(BigDecimal value, int scale) {

		return arredondar(value, scale, RoundingMode.DOWN);
	}

	/**
	 * Soma os valores do campo (utilizando {@linkplain nomeCampo}) dos {@link itens} para calcular a diferença entre o
	 * {@linkplain total}.<br>
	 * <br>
	 * O valor {@linkplain total} e os valores da lista, não podem ter diferença de casas decimais.<br>
	 * Para evitar isto, será utilizado a quantidade de casas decimais do {@linkplain total} se a quantidade de casas for maior ou
	 * igual a 2.<br>
	 * Caso contrário será utilizado 2 casas decimais.
	 * <ul>
	 * <li>Se a diferença for igual a zero, retorna e não faz nada.</li>
	 * <li>Se a diferença for maior que zero, aplica no valor do campo (utilizando {@linkplain nomeCampo}) do primeiro item da
	 * lista de {@linkplain itens}.</li>
	 * <li>Se a diferença for menor que zero, procura na lista de {@linkplain itens} um item que tenha o valor maior que a
	 * difereça para aplicar.</li>
	 * </ul>
	 * 
	 * @param itens Itens para somar e aplicar a diferença.
	 * @param total Valor original para calcular a diferença.
	 * @param nomeCampo Nome do campo para obter a somatória dos itens.
	 * @param classe Tipo dos itens da lista.
	 * @throws VUtilsRuntimeException Se não for possível aplicar a diferença em nenhum item.
	 */
	public static void redistribuirValoresDizima(List<? extends Object> itens, BigDecimal total, String nomeCampo, Class<? extends Object> classe)
			throws Exception {

		int scale = total.scale() >= SCALE_MONEY ? total.scale() : SCALE_MONEY;
		redistribuirValoresDizima(itens, total, nomeCampo, classe, scale);
	}

	/**
	 * Soma os valores do campo (utilizando {@linkplain nomeCampo}) dos {@link itens} para calcular a diferença entre o
	 * {@linkplain total}.
	 * <ul>
	 * <li>Se a diferença for igual a zero, retorna e não faz nada.</li>
	 * <li>Se a diferença for maior que zero, aplica no valor do campo (utilizando {@linkplain nomeCampo}) do primeiro item da
	 * lista de {@linkplain itens}.</li>
	 * <li>Se a diferença for menor que zero, procura na lista de {@linkplain itens} um item que tenha o valor maior que a
	 * difereça para aplicar.</li>
	 * </ul>
	 * 
	 * @param itens Itens para somar e aplicar a diferença.
	 * @param total Valor original para calcular a diferença.
	 * @param nomeCampo Nome do campo para obter a somatória dos itens.
	 * @param classe Tipo dos itens da lista.
	 * @param casasDecimais Quantidade de casas decimais para truncar o {@linkplain total} e a soma dos valores dos
	 *            {@linkplain itens}.
	 * @throws VUtilsRuntimeException Se não for possível aplicar a diferença em nenhum item.
	 */
	public static void redistribuirValoresDizima(List<? extends Object> itens, BigDecimal total, String nomeCampo, Class<? extends Object> classe, int casasDecimais)
			throws Exception {


		if (isZero(total))
			return;

		BigDecimal totalTruncado = truncar(total, casasDecimais);

		try {

			BigDecimal acumulador = BigDecimal.ZERO;

			for (Object item : itens) {
				Field campo = getField(classe, nomeCampo);
				BigDecimal valorCampo = truncar(BigDecimalUtils.parseToBigDecimalOrZero(campo.get(item)), casasDecimais);

				acumulador = acumulador.add(valorCampo);
			}

			BigDecimal diferenca = totalTruncado.subtract(acumulador);
			setarDiferenca(itens, classe, nomeCampo, diferenca);

		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static void redistribuirValoresDiferenca(List<? extends Object> itens, BigDecimal total, BigDecimal totalCalculado, String nomeCampo, Class<? extends Object> classe)
			throws Exception {

		if (isZero(total))
			return;

		try {

			BigDecimal diferenca = total.subtract(totalCalculado);
			setarDiferenca(itens, classe, nomeCampo, diferenca);

		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
	
	private static void setarDiferenca(List<? extends Object> itens, Class<? extends Object> classe, String nomeAtributo, BigDecimal diferenca)
			throws Exception {

		if (isZero(diferenca))
			return;

		Field campo = getField(classe, nomeAtributo);

		if (isLessThanZero(diferenca)) {
			// Caso a diferenca seja negativa remove valor dos últimos itens para o primeiro, se disponível.
			// Se o valor do campo for menor que a diferença, zera o valor do campo e diminui da diferença para passar ao próximo
			// item.

			for (int i = itens.size() - 1; i >= 0; i--) {

				Object item = itens.get(i);
				BigDecimal valor = parseToBigDecimalOrZero(campo.get(item));

				if (isLessOrEqualThanZero(valor))
					continue;

				BigDecimal valorComDiferenca = BigDecimal.ZERO;

				if (isGreaterThan(diferenca.abs(), valor)) {

					campo.set(item, BigDecimal.ZERO);
					diferenca = diferenca.add(valor);

				} else {
					valorComDiferenca = valor.add(diferenca);

					if (isGreaterOrEqualThanZero(valorComDiferenca)) {
						campo.set(item, valorComDiferenca);
						return;
					}
				}

			}

			// Não conseguiu aplicar a diferença porque o valor final do item ficaria negativo.
			throw new Exception("Não foi possível aplicar a diferença em nenhum dos itens da lista.");

		} else {
			// Caso a diferenca seja maior que zero, soma ao primeiro elemento.

			Object item = itens.get(0);
			BigDecimal valor = (BigDecimal) campo.get(item);
			campo.set(item, valor.add(diferenca));
		}
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
	 * Utilizar o método formatarValorMonetario()
	 */
	@Deprecated
	public static String toString(BigDecimal valor) {

		return toString(valor, false);
	}

	/**
	 * Utilizar o método formatarValorMonetario()
	 */
	@Deprecated
	public static String toString(BigDecimal valor, boolean usaSeparadorMilhar) {

		return toString(valor, usaSeparadorMilhar, SCALE_MONEY);
	}

	/**
	 * Utilizar o método formatarValorMonetario()
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

	/**
	 * Formata um valor para uma string no formato percentual <br>
	 * Exemplos: <br>
	 * 15.15 -> 15,15% <br>
	 * 20 -> 20,00%
	 */
	public static String formatarPorcentagem(BigDecimal valor) {

		if (valor == null)
			return StringUtils.EMPTY;

		NumberFormat percentFormat = NumberFormat.getPercentInstance();
		percentFormat.setMaximumFractionDigits(2);
		percentFormat.setMinimumFractionDigits(2);

		return percentFormat.format(dividePorCem(valor));
	}
}